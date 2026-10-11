use super::*;

#[test]
fn throttle_backend_rejects_rebinding_noncanonical_limits_and_outage() {
    let store = Arc::new(RecordingThrottleStore::default());
    let empty = empty_session_throttle_snapshot(super::super::SessionThrottleKey {
        tenant_id: tenant(),
        session_id: session(),
    })
    .unwrap_or_else(|error| panic!("empty throttle snapshot: {error}"));
    let base = session_throttle_version_hash(&empty)
        .unwrap_or_else(|error| panic!("empty throttle version: {error}"));
    let apply = throttle_request(EffectOperation::Apply, base);
    let port = throttle_port(store.clone());
    port.execute(&apply)
        .unwrap_or_else(|error| panic!("apply throttle before hostility: {error}"));

    let mut wrong_action = query(&apply);
    wrong_action.action_id = ActionId::new("action-throttle-wrong")
        .unwrap_or_else(|error| panic!("wrong throttle action: {error}"));
    assert_eq!(
        require_error(port.load_result(&wrong_action)).kind(),
        PortErrorKind::Conflict
    );
    let mut wrong_plan = query(&apply);
    wrong_plan.plan_hash = Digest32::new([81_u8; 32]);
    let mut wrong_effect = query(&apply);
    wrong_effect.effect_id = EffectId::new("effect-throttle-wrong")
        .unwrap_or_else(|error| panic!("wrong throttle effect: {error}"));
    let mut wrong_contribution = query(&apply);
    wrong_contribution.contribution_hash = Digest32::new([82_u8; 32]);
    let mut wrong_fence = query(&apply);
    wrong_fence.scheduler_fencing_token = 83;
    for wrong in [wrong_plan, wrong_effect, wrong_contribution, wrong_fence] {
        assert_eq!(
            require_error(port.load_result(&wrong)).kind(),
            PortErrorKind::Conflict
        );
    }
    let mut rebound = apply.clone();
    rebound.target = ResponseTarget::Session {
        session_id: SessionId::new("session-throttle-rebound")
            .unwrap_or_else(|error| panic!("rebound throttle session: {error}")),
    };
    assert_eq!(
        require_error(port.execute(&rebound)).kind(),
        PortErrorKind::Conflict
    );
    let mut cross_tenant = apply.clone();
    cross_tenant.tenant_id = TenantId::new("tenant-throttle-rebound")
        .unwrap_or_else(|error| panic!("rebound throttle tenant: {error}"));
    assert_eq!(
        require_error(port.execute(&cross_tenant)).kind(),
        PortErrorKind::Conflict
    );

    let mut noncanonical = throttle_request(EffectOperation::Apply, base);
    let bytes = br#"{"window_ms":5000, "max_invocations":3}"#.to_vec();
    noncanonical.canonical_contribution = CanonicalBody::new(bytes.clone())
        .unwrap_or_else(|error| panic!("noncanonical throttle limits: {error}"));
    noncanonical.contribution_hash = Digest32::new(*chio_core::sha256(&bytes).as_bytes());
    noncanonical.idempotency_key = RecordId::new("response_effect_command:throttle-noncanonical")
        .unwrap_or_else(|error| panic!("noncanonical throttle command: {error}"));
    assert_eq!(
        require_error(port.execute(&noncanonical)).kind(),
        PortErrorKind::IntegrityFailure
    );

    store.fail();
    assert_eq!(
        require_error(port.load_result(&query(&apply))).kind(),
        PortErrorKind::Unavailable
    );
}
