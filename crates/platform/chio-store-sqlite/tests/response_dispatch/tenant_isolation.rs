use super::*;
use chio_security_types::ports::PortError;

#[test]
fn exact_dispatch_id_cannot_cross_tenants_after_restart() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("directory: {error}"));
    let path = directory.path().join("tenant-dispatch.sqlite");
    let now = now_unix_ms();
    let request = dispatch_request("exact-action", "exact-dispatch", now, now, now + 10_000);
    let store =
        SqliteSecurityStateStore::open(&path).unwrap_or_else(|error| panic!("store: {error}"));
    let committed = match store
        .commit_dispatch(&request)
        .unwrap_or_else(|error| panic!("commit: {error}"))
    {
        ResponseDispatchCommitOutcome::Committed(record) => record,
        _ => panic!("fresh dispatch did not commit"),
    };
    let recovery = ResponseDispatchRecoveryRequest {
        key: request.authorization.body.key.clone(),
        action_id: request.authorization.body.action_id.clone(),
        recovery_id: record_id("exact-recovery"),
        lease_owner_id: request.initial_lease.lease_owner_id.clone(),
        expected_fencing_token: Some(committed.initial_work.fencing_token),
        now_unix_ms: now,
        lease_expires_at_unix_ms: now + 10_000,
    };
    let recovered = store
        .recover_dispatch_work(&recovery)
        .unwrap_or_else(|error| panic!("owned recovery: {error}"));
    let check = |store: &SqliteSecurityStateStore| {
        let mut key = request.authorization.body.key.clone();
        assert_eq!(
            store
                .load_dispatch(&key)
                .unwrap_or_else(|error| panic!("owned: {error}")),
            ResponseDispatchLoadOutcome::Found(Box::new(committed.clone()))
        );
        key.tenant_id =
            TenantId::new("foreign-tenant").unwrap_or_else(|error| panic!("tenant: {error}"));
        assert_eq!(
            store
                .load_dispatch(&key)
                .unwrap_or_else(|error| panic!("foreign: {error}")),
            ResponseDispatchLoadOutcome::Missing
        );
        assert_eq!(
            store
                .recover_dispatch_work(&recovery)
                .unwrap_or_else(|error| panic!("owned recovery replay: {error}")),
            recovered
        );
        let mut foreign = recovery.clone();
        foreign.key = key;
        assert_eq!(
            store.recover_dispatch_work(&foreign),
            Err(PortError::invalid_data())
        );
    };
    check(&store);
    drop(store);
    check(&SqliteSecurityStateStore::open(&path).unwrap_or_else(|error| panic!("reopen: {error}")));
}
