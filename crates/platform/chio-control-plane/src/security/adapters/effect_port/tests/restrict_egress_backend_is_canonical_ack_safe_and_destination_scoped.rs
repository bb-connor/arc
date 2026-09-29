use super::*;

#[test]
fn restrict_egress_backend_is_canonical_ack_safe_and_destination_scoped() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = Arc::new(
        SqliteSecurityStateStore::open(directory.path().join("response-egress.db"))
            .unwrap_or_else(|error| panic!("open SQLite store: {error}")),
    );
    let now = now_unix_ms();
    let action_id = ActionId::new("action-a").unwrap_or_else(|error| panic!("action id: {error}"));
    let plan_body =
        CanonicalBody::new(b"{}".to_vec()).unwrap_or_else(|error| panic!("plan body: {error}"));
    store
        .create(&ResponsePlanRecord {
            tenant_id: tenant(),
            action_id: action_id.clone(),
            generation: 0,
            state: RecordId::new("active").unwrap_or_else(|error| panic!("plan state: {error}")),
            canonical_body: plan_body.clone(),
            body_hash: Digest32::new(*chio_core::sha256(plan_body.as_bytes()).as_bytes()),
            due_at_unix_ms: Some(now.saturating_sub(1)),
        })
        .unwrap_or_else(|error| panic!("create scheduled response: {error}"));
    let work = store
        .claim_due(&SchedulerClaimRequest {
            tenant_id: tenant(),
            claim_id: RecordId::new("effect-port-egress-claim")
                .unwrap_or_else(|error| panic!("claim id: {error}")),
            lease_owner_id: LeaseOwnerId::new("effect-port-egress-worker")
                .unwrap_or_else(|error| panic!("lease owner: {error}")),
            now_unix_ms: now,
            lease_expires_at_unix_ms: now.saturating_add(60_000),
            max_claims: 1,
        })
        .unwrap_or_else(|error| panic!("claim response: {error}"));
    assert_eq!(work.len(), 1);

    let key = EgressRestrictionSessionKey {
        tenant_id: tenant(),
        session_id: session(),
    };
    let base = egress_restriction_version_hash(store.as_ref(), &key)
        .unwrap_or_else(|error| panic!("egress base version: {error}"));
    let backend = Arc::new(RestrictEgressOverlayBackend::new(store.clone()));
    ResponseEffectBackend::ensure_ready(backend.as_ref())
        .unwrap_or_else(|error| panic!("egress readiness: {error}"));
    let routed: Arc<dyn ResponseEffectBackend> = backend;
    let port = ActiveResponseEffectPort::from_backends(vec![routed])
        .unwrap_or_else(|error| panic!("egress router: {error}"));

    let malformed = egress_request(EffectOperation::Apply, base, &["server-b", "server-a"]);
    let malformed_error = require_error(port.execute(&malformed));
    assert_eq!(malformed_error.kind(), PortErrorKind::InvalidData);

    let mut apply = egress_request(EffectOperation::Apply, base, &["server-a", "server-b"]);
    apply.scheduler_fencing_token = work[0].fencing_token;
    apply.plan_expires_at_unix_ms = now.saturating_add(30_000);
    let applied = port
        .execute(&apply)
        .unwrap_or_else(|error| panic!("apply egress restriction: {error}"));
    assert!(applied.applied);
    assert_eq!(
        port.load_result(&query(&apply)),
        Ok(EffectExecutionStatus::Completed {
            result: applied.clone()
        })
    );
    assert_eq!(port.execute(&apply), Ok(applied.clone()));

    let matching = store
        .evaluate_destination(&chio_security_types::ports::EgressDestinationQuery {
            key: key.clone(),
            destination_id: chio_security_types::ports::DestinationId::new("server-a")
                .unwrap_or_else(|error| panic!("matching destination: {error}")),
        })
        .unwrap_or_else(|error| panic!("matching decision: {error}"));
    let nonmatching = store
        .evaluate_destination(&chio_security_types::ports::EgressDestinationQuery {
            key: key.clone(),
            destination_id: chio_security_types::ports::DestinationId::new("server-c")
                .unwrap_or_else(|error| panic!("nonmatching destination: {error}")),
        })
        .unwrap_or_else(|error| panic!("nonmatching decision: {error}"));
    assert!(matching.denied);
    assert!(!nonmatching.denied);

    let mut rebound = apply.clone();
    rebound.effect_id =
        EffectId::new("effect-rebound").unwrap_or_else(|error| panic!("rebound effect: {error}"));
    rebound.target = ResponseTarget::Session {
        session_id: SessionId::new("session-rebound")
            .unwrap_or_else(|error| panic!("rebound session: {error}")),
    };
    let rebound_error = require_error(port.execute(&rebound));
    assert_eq!(rebound_error.kind(), PortErrorKind::Conflict);

    let mut remove = apply;
    remove.operation = EffectOperation::Remove;
    remove.expected_version_hash = applied.resulting_version_hash;
    remove.idempotency_key = RecordId::new("response_effect_command:egress-remove")
        .unwrap_or_else(|error| panic!("remove command: {error}"));
    let removed = port
        .execute(&remove)
        .unwrap_or_else(|error| panic!("remove egress restriction: {error}"));
    assert!(!removed.applied);
    assert_eq!(
        port.load_result(&query(&remove)),
        Ok(EffectExecutionStatus::Completed {
            result: removed.clone()
        })
    );
    assert_eq!(port.execute(&remove), Ok(removed.clone()));
    assert!(
        !store
            .evaluate_destination(&chio_security_types::ports::EgressDestinationQuery {
                key,
                destination_id: chio_security_types::ports::DestinationId::new("server-a")
                    .unwrap_or_else(|error| panic!("final destination: {error}")),
            })
            .unwrap_or_else(|error| panic!("final decision: {error}"))
            .denied
    );
}
