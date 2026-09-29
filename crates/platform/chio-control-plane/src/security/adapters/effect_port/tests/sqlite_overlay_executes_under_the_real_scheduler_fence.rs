use super::*;


#[test]
fn sqlite_overlay_executes_under_the_real_scheduler_fence() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = Arc::new(
        SqliteSecurityStateStore::open(directory.path().join("response-effects.db"))
            .unwrap_or_else(|error| panic!("open SQLite store: {error}")),
    );
    let now = now_unix_ms();
    let action_id =
        ActionId::new("action-a").unwrap_or_else(|error| panic!("action id: {error}"));
    let plan_body =
        CanonicalBody::new(b"{}".to_vec()).unwrap_or_else(|error| panic!("plan body: {error}"));
    let plan = ResponsePlanRecord {
        tenant_id: tenant(),
        action_id: action_id.clone(),
        generation: 0,
        state: RecordId::new("active").unwrap_or_else(|error| panic!("plan state: {error}")),
        canonical_body: plan_body.clone(),
        body_hash: Digest32::new(*chio_core::sha256(plan_body.as_bytes()).as_bytes()),
        due_at_unix_ms: Some(now.saturating_sub(1)),
    };
    store
        .create(&plan)
        .unwrap_or_else(|error| panic!("create scheduled response: {error}"));
    let work = store
        .claim_due(&SchedulerClaimRequest {
            tenant_id: tenant(),
            claim_id: RecordId::new("effect-port-sqlite-claim")
                .unwrap_or_else(|error| panic!("claim id: {error}")),
            lease_owner_id: LeaseOwnerId::new("effect-port-worker")
                .unwrap_or_else(|error| panic!("lease owner: {error}")),
            now_unix_ms: now,
            lease_expires_at_unix_ms: now.saturating_add(60_000),
            max_claims: 1,
        })
        .unwrap_or_else(|error| panic!("claim response: {error}"));
    assert_eq!(work.len(), 1);

    let target = session_containment_target(&tenant(), &session())
        .unwrap_or_else(|error| panic!("target: {error}"));
    let base = session_overlay_version_hash(store.as_ref(), &target)
        .unwrap_or_else(|error| panic!("base version: {error}"));
    let port = ActiveResponseEffectPort::session_suspension_only(Arc::new(
        SessionSuspensionOverlayBackend::new(store.clone()),
    ));
    let mut apply = request(EffectOperation::Apply, base, 6);
    apply.scheduler_fencing_token = work[0].fencing_token;
    apply.plan_expires_at_unix_ms = now.saturating_add(30_000);
    let applied = port
        .execute(&apply)
        .unwrap_or_else(|error| panic!("apply through SQLite: {error}"));
    assert!(applied.applied);

    let mut remove = apply;
    remove.operation = EffectOperation::Remove;
    remove.expected_version_hash = applied.resulting_version_hash;
    remove.idempotency_key = RecordId::new("response_effect_command:sqlite-remove")
        .unwrap_or_else(|error| panic!("remove command: {error}"));
    let removed = port
        .execute(&remove)
        .unwrap_or_else(|error| panic!("remove through SQLite: {error}"));
    assert!(!removed.applied);
    assert!(store
        .load_effective(&target)
        .unwrap_or_else(|error| panic!("load final overlay: {error}"))
        .unwrap_or_else(|| panic!("final overlay state missing"))
        .active_contributions
        .is_empty());
}
