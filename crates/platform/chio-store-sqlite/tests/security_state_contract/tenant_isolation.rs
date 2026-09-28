//! Exact identifiers are lookup keys, never tenant read authority.
use super::super::*;
use chio_test_support::prelude::*;

fn foreign_tenant() -> TenantId {
    TenantId::new("tenant-exact-foreign").test_expect("foreign tenant")
}

fn assert_isolated_reads<S>(store: &S) -> PortResult<()>
where
    S: FlowStateStore
        + SecurityEventStore
        + ResponseStore
        + ContainmentOverlayStore
        + LineageFenceStore,
{
    let mut flow = flow_key("exact-tenant-flow", "epoch-base");
    assert!(store.load(&flow)?.is_some());
    flow.tenant_id = foreign_tenant();
    assert_eq!(store.load(&flow)?, None);

    let mut partition = correlation_key(71);
    let through = store
        .load_correlation_max_seen_event_time(&partition)?
        .test_expect("owned event time");
    let scan = scan_for(&partition, through);
    assert_eq!(store.scan_partition(&scan)?.events.len(), 1);
    assert!(store.load_correlation(&partition)?.is_some());
    assert!(store
        .load_correlation_max_seen_event_time(&partition)?
        .is_some());
    let mut outcome_key = CorrelationOutcomeKey {
        tenant_id: partition.tenant_id.clone(),
        rule_id: partition.rule_id.clone(),
        event_id: EventId::new("exact-tenant-event").test_expect("event"),
    };
    assert!(store.load_correlation_outcome(&outcome_key)?.is_some());
    outcome_key.tenant_id = foreign_tenant();
    assert_eq!(store.load_correlation_outcome(&outcome_key)?, None);
    partition.tenant_id = foreign_tenant();
    assert_eq!(store.load_correlation(&partition)?, None);
    assert_eq!(
        store.load_correlation_max_seen_event_time(&partition)?,
        None
    );
    let scan = scan_for(&partition, through);
    let foreign_scan = store.scan_partition(&scan)?;
    assert!(foreign_scan.events.is_empty());
    assert_eq!(foreign_scan.partition_generation, 0);

    let mut plan = ResponsePlanKey {
        tenant_id: tenant(),
        action_id: action("exact-tenant-response"),
    };
    assert!(store.load_plan(&plan)?.is_some());
    plan.tenant_id = foreign_tenant();
    assert_eq!(store.load_plan(&plan)?, None);

    let mut effect_key = ResponseEffectKey {
        tenant_id: tenant(),
        effect_id: effect("exact-tenant-effect"),
    };
    assert!(store.load_effect(&effect_key)?.is_some());
    effect_key.tenant_id = foreign_tenant();
    assert_eq!(store.load_effect(&effect_key)?, None);

    let mut target = overlay_target("binding-contract-session");
    let owned = store.load_effective(&target)?.test_expect("tenant overlay");
    assert_eq!(owned.active_contributions.len(), 2);
    target.tenant_id = foreign_tenant();
    assert_eq!(store.load_effective(&target)?, None);

    let mut fence = scoped_action("exact-tenant-fence");
    assert!(store.query(&fence)?.is_some());
    fence.tenant_id = foreign_tenant();
    assert_eq!(store.query(&fence)?, None);
    for event in isolated_advisories() {
        assert_eq!(store.append_advisory(&event)?, EventAppend::Duplicate);
    }
    Ok(())
}

fn isolated_advisories() -> [AdvisorySecurityEvent; 2] {
    let owned = advisory_event("exact-advisory", 1);
    let mut foreign = owned.clone();
    foreign.tenant_id = foreign_tenant();
    foreign.canonical_body = body(br#"{"foreign":true}"#);
    foreign.body_hash = digest(foreign.canonical_body.as_bytes());
    [owned, foreign]
}

fn populate<S>(store: &S) -> PortResult<()>
where
    S: FlowStateStore
        + SecurityEventStore
        + ResponseStore
        + ContainmentOverlayStore
        + LineageFenceStore,
{
    let now = now_unix_ms();
    let expiry = now.checked_add(120_000).test_expect("fixture expiry");
    store.join(&FlowJoinRequest {
        key: flow_key("exact-tenant-flow", "epoch-base"),
        principal_join: label("private-principal"),
        lineage_join: label("private-lineage"),
        session_join: label("private-session"),
        transition_id: record("exact-tenant-flow-transition"),
    })?;

    let event = verified_event("exact-tenant-event", now);
    let partition = correlation_key(71);
    store.append_verified(&event)?;
    store.index_partition_event(&CorrelationEventIndexRequest {
        key: partition.clone(),
        event_id: event.event_id.clone(),
        transition_id: record("exact-tenant-index"),
    })?;
    let scan = scan_for(&partition, now);
    let observed = store.scan_partition(&scan)?;
    assert_eq!(observed.events.as_slice(), std::slice::from_ref(&event));
    store.commit_correlation_outcome(&CorrelationOutcomeCommitRequest {
        correlation: CorrelationCasRequest {
            scan,
            observed_partition_generation: observed.partition_generation,
            partial: partial(&partition, 0, now),
            expected_generation: None,
            transition_id: record("exact-tenant-correlation"),
        },
        outcome: correlation_outcome_publication(&partition, &event, 71),
    })?;
    for event in isolated_advisories() {
        assert_eq!(store.append_advisory(&event)?, EventAppend::Inserted);
    }

    store.create(&response_plan("exact-tenant-response", 0, Some(now - 1)))?;
    let claim = claim_request("exact-tenant-owner", now, expiry);
    let foreign_claim = SchedulerClaimRequest {
        tenant_id: foreign_tenant(),
        ..claim.clone()
    };
    assert!(store.claim_due(&foreign_claim)?.is_empty());
    let work = store.claim_due(&claim)?;
    assert_eq!(work.len(), 1);
    let owned = &work[0];
    store.persist_effect(&response_effect(
        &owned.action_id,
        "exact-tenant-effect",
        &owned.lease_owner_id,
        owned.fencing_token,
    ))?;
    store.acquire(&fence_request("exact-tenant-fence", expiry))?;
    exercise_overlay_action_binding_contract(store);
    assert_isolated_reads(store)
}

#[test]
fn exact_identifiers_cannot_cross_tenants_in_model() -> PortResult<()> {
    populate(&ModelStore::default())
}

#[test]
fn exact_identifiers_cannot_cross_tenants_in_sqlite_or_after_restart() {
    let directory = tempdir().test_expect("directory");
    let path = directory.path().join("exact-tenants.sqlite");
    let store = SqliteSecurityStateStore::open(&path).test_expect("store");
    populate(&store).test_expect("tenant boundaries");
    drop(store);
    let reopened = SqliteSecurityStateStore::open(&path).test_expect("reopen");
    assert_isolated_reads(&reopened).test_expect("durable tenant boundaries");
}

fn populate_colliding_flow_scopes<S: FlowStateStore>(store: &S) -> PortResult<EgressFence> {
    let mut request = FlowJoinRequest {
        key: flow_key("same-flow-identifiers", "same-epoch"),
        principal_join: label("owner-principal"),
        lineage_join: label("owner-lineage"),
        session_join: label("owner-session"),
        transition_id: record("same-transition"),
    };
    let owned = store.join(&request)?;
    let fence = store.acquire_egress_fence(&EgressFenceRequest {
        key: request.key.clone(),
        request_id: RequestId::new("same-egress-request").test_expect("request"),
        request_hash: Digest32::new([91; 32]),
        expected_context_generation: owned.context_generation,
        expires_at_unix_ms: now_unix_ms().checked_add(120_000).test_expect("expiry"),
    })?;
    request.key.tenant_id = foreign_tenant();
    request.principal_join = InformationLabel::bottom();
    request.lineage_join = InformationLabel::bottom();
    request.session_join = InformationLabel::bottom();
    let other = store.join(&request)?;
    assert_eq!(other.key, request.key);
    assert_eq!(other.session_label, InformationLabel::bottom());
    assert_eq!(store.join(&request)?, other);
    request.session_join = label("changed-replay");
    assert_eq!(store.join(&request), Err(PortError::conflict()));
    assert_colliding_flow_scopes(store, &fence)?;
    Ok(fence)
}

fn assert_colliding_flow_scopes<S: FlowStateStore>(
    store: &S,
    fence: &EgressFence,
) -> PortResult<()> {
    let owned = store.load(&fence.key)?.test_expect("owned flow");
    assert_eq!(owned.principal_label, label("owner-principal"));
    assert_eq!(owned.lineage_label, label("owner-lineage"));
    assert_eq!(
        owned.session_label,
        label("owner-session")
            .join_restrictions(&label("owner-principal"))
            .and_then(|joined| joined.join_restrictions(&label("owner-lineage")))
            .test_expect("session includes its principal and lineage restrictions")
    );
    store.validate_egress_fence(fence)?;
    let mut foreign = fence.clone();
    foreign.key.tenant_id = foreign_tenant();
    let other = store
        .load(&foreign.key)?
        .test_expect("independent foreign flow");
    assert_eq!(other.principal_label, InformationLabel::bottom());
    assert_eq!(other.lineage_label, InformationLabel::bottom());
    assert_eq!(other.session_label, InformationLabel::bottom());
    assert_eq!(
        store.validate_egress_fence(&foreign),
        Err(PortError::invalid_data())
    );
    Ok(())
}

#[test]
fn colliding_flow_identifiers_do_not_inherit_foreign_labels_or_fences_in_model() -> PortResult<()> {
    populate_colliding_flow_scopes(&ModelStore::default()).map(|_| ())
}

#[test]
fn colliding_flow_identifiers_do_not_inherit_foreign_labels_or_fences_after_restart() {
    let directory = tempdir().test_expect("directory");
    let path = directory.path().join("colliding-flow.sqlite");
    let store = SqliteSecurityStateStore::open(&path).test_expect("store");
    let fence = populate_colliding_flow_scopes(&store).test_expect("independent scopes");
    drop(store);
    let reopened = SqliteSecurityStateStore::open(&path).test_expect("reopen");
    assert_colliding_flow_scopes(&reopened, &fence).test_expect("durable independent scopes");
}
