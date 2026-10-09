use super::*;

const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn identifier(field: &'static str, value: &str) -> AdmissionIdentifier {
    AdmissionIdentifier::try_new(field, value).expect("test identifier must be valid")
}

fn tool_dispatch(namespace: AuthenticatedRequestNamespace) -> AdmissionOperationBindingV1 {
    let digest = |field| AdmissionDigest::try_new(field, HASH).expect("test digest must be valid");
    AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
        kind: AdmissionOperationKind::ToolDispatch,
        namespace,
        request_id: identifier("request_id", "process:shared"),
        capability_id: identifier("capability_id", "cap-1"),
        authorization_capability_hash: digest("authorization_capability_hash"),
        request_binding: AdmissionRequestBindingV1::new(
            digest("immutable_request_hash"),
            AdmissionParticipantRequirements {
                broker_attempt: true,
                budget_capture: true,
                ..AdmissionParticipantRequirements::NONE
            },
        )
        .expect("test request binding must derive"),
        policy_hash: digest("policy_hash"),
        effect_class: SideEffectClass::SideEffecting,
    })
    .expect("test binding must derive")
}

#[test]
fn a_signed_receipt_selects_only_its_own_namespace_replay_key() {
    let coordinator = || identifier("coordinator_authority_id", "store-1");
    let request_id = || identifier("request_id", "process:shared");
    let local = tool_dispatch(
        AuthenticatedRequestNamespace::for_local_system(coordinator())
            .expect("local namespace must derive"),
    );
    let tenant = tool_dispatch(
        AuthenticatedRequestNamespace::from_authentication_context(coordinator(), "tenant-a")
            .expect("tenant namespace must derive"),
    );
    let other_coordinator = tool_dispatch(
        AuthenticatedRequestNamespace::for_local_system(identifier(
            "coordinator_authority_id",
            "store-2",
        ))
        .expect("local namespace must derive"),
    );

    let unscoped = AdmissionReplayKey::for_signed_receipt(coordinator(), None, request_id())
        .expect("local receipt key must derive");
    let scoped =
        AdmissionReplayKey::for_signed_receipt(coordinator(), Some("tenant-a"), request_id())
            .expect("tenant receipt key must derive");

    assert_eq!(unscoped, local.replay_key());
    assert_eq!(scoped, tenant.replay_key());
    assert_ne!(unscoped, scoped);
    assert_ne!(unscoped, other_coordinator.replay_key());
    assert_eq!(
        AdmissionReplayKey::for_signed_receipt(
            coordinator(),
            Some(LOCAL_SYSTEM_TENANT_ID),
            request_id()
        ),
        Err(AdmissionOperationError::ReservedLocalSystemTenant)
    );
}
