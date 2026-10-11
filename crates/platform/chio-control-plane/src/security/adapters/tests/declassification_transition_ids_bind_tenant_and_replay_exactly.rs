use super::*;

#[test]
fn declassification_transition_ids_bind_tenant_and_replay_exactly() {
    let tenant_a = TenantId::new("tenant-a").unwrap_or_else(|error| panic!("tenant a: {error}"));
    let tenant_b = TenantId::new("tenant-b").unwrap_or_else(|error| panic!("tenant b: {error}"));
    let grant = GrantId::new("shared-grant").unwrap_or_else(|error| panic!("grant: {error}"));
    let request_hash = Digest32::new([17_u8; 32]);
    let request_id =
        RequestId::new("shared-request").unwrap_or_else(|error| panic!("request id: {error}"));
    let dispatch_id =
        RecordId::new("shared-dispatch").unwrap_or_else(|error| panic!("dispatch id: {error}"));
    let first_binding = DeclassificationTransitionBinding::Consumption {
        tenant_id: tenant_a.clone(),
        grant_id: grant.clone(),
        request_hash,
        request_id: request_id.clone(),
    };
    let first = derive_declassification_transition_id(&first_binding)
        .unwrap_or_else(|error| panic!("first transition: {error}"));
    let replay = derive_declassification_transition_id(&first_binding)
        .unwrap_or_else(|error| panic!("replay transition: {error}"));
    let other_tenant =
        derive_declassification_transition_id(&DeclassificationTransitionBinding::Consumption {
            tenant_id: tenant_b.clone(),
            grant_id: grant.clone(),
            request_hash,
            request_id: request_id.clone(),
        })
        .unwrap_or_else(|error| panic!("other tenant transition: {error}"));
    assert_eq!(first, replay);
    assert_ne!(first, other_tenant);
    let outcome_a =
        derive_declassification_transition_id(&DeclassificationTransitionBinding::Released {
            tenant_id: tenant_a,
            grant_id: grant.clone(),
            request_hash,
            request_id: request_id.clone(),
            dispatch_commitment_id: dispatch_id.clone(),
        })
        .unwrap_or_else(|error| panic!("tenant a outcome transition: {error}"));
    let outcome_b =
        derive_declassification_transition_id(&DeclassificationTransitionBinding::Released {
            tenant_id: tenant_b,
            grant_id: grant,
            request_hash,
            request_id,
            dispatch_commitment_id: dispatch_id,
        })
        .unwrap_or_else(|error| panic!("tenant b outcome transition: {error}"));
    assert_ne!(outcome_a, outcome_b);
}
