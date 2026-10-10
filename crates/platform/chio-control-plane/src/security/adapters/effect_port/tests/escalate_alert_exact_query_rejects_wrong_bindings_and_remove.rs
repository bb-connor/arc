use super::*;

#[test]
fn escalate_alert_exact_query_rejects_wrong_bindings_and_remove() {
    let store = Arc::new(RecordingAlertStore::default());
    let port = alert_port(store.clone());
    let request = alert_request();
    port.execute(&request)
        .unwrap_or_else(|error| panic!("execute bound alert: {error}"));

    let mut wrong_tenant = query(&request);
    wrong_tenant.tenant_id =
        TenantId::new("tenant-wrong").unwrap_or_else(|error| panic!("wrong tenant: {error}"));
    wrong_tenant.target = ResponseTarget::Tenant {
        tenant_id: wrong_tenant.tenant_id.clone(),
    };
    let mut wrong_action = query(&request);
    wrong_action.action_id =
        ActionId::new("action-wrong").unwrap_or_else(|error| panic!("wrong action: {error}"));
    let mut wrong_plan = query(&request);
    wrong_plan.plan_hash = Digest32::new([41_u8; 32]);
    let mut wrong_effect = query(&request);
    wrong_effect.effect_id =
        EffectId::new("effect-wrong").unwrap_or_else(|error| panic!("wrong effect: {error}"));
    let mut wrong_contribution = query(&request);
    wrong_contribution.contribution_hash = Digest32::new([42_u8; 32]);
    let mut wrong_fence = query(&request);
    wrong_fence.scheduler_fencing_token = 43;
    for wrong in [
        wrong_tenant,
        wrong_action,
        wrong_plan,
        wrong_effect,
        wrong_contribution,
        wrong_fence,
    ] {
        assert_eq!(
            port.load_result(&wrong),
            Ok(EffectExecutionStatus::NotExecuted)
        );
    }

    let mut tenant_rebound = request.clone();
    tenant_rebound.target = ResponseTarget::Tenant {
        tenant_id: TenantId::new("tenant-rebound")
            .unwrap_or_else(|error| panic!("rebound tenant: {error}")),
    };
    assert_eq!(
        require_error(port.execute(&tenant_rebound)).kind(),
        PortErrorKind::InvalidData
    );

    let mut noncanonical = request.clone();
    let noncanonical_bytes = br#"{"z":1,"a":2}"#.to_vec();
    noncanonical.canonical_contribution = CanonicalBody::new(noncanonical_bytes.clone())
        .unwrap_or_else(|error| panic!("noncanonical alert body: {error}"));
    noncanonical.contribution_hash =
        Digest32::new(*chio_core::sha256(&noncanonical_bytes).as_bytes());
    assert_eq!(
        require_error(port.execute(&noncanonical)).kind(),
        PortErrorKind::IntegrityFailure
    );

    let mut wrong_hash = request.clone();
    wrong_hash.contribution_hash = Digest32::new([44_u8; 32]);
    assert_eq!(
        require_error(port.execute(&wrong_hash)).kind(),
        PortErrorKind::IntegrityFailure
    );

    let mut remove = request;
    remove.operation = EffectOperation::Remove;
    remove.idempotency_key = RecordId::new("response_effect_command:alert-remove")
        .unwrap_or_else(|error| panic!("remove command: {error}"));
    assert_eq!(
        require_error(port.execute(&remove)).kind(),
        PortErrorKind::InvalidData
    );
    assert_eq!(store.counts().0, 1);
}
