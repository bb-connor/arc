use chio_security_types::ports::{RecordId, TenantId};
use chio_security_types::{
    is_legal_response_transition, ResponseEffectKind, ResponseMutationRecord,
    ResponseRequestedRecord, ResponseState, ResponseTarget,
};

const STATES: [ResponseState; 12] = [
    ResponseState::Planned,
    ResponseState::AwaitingApproval,
    ResponseState::Applying,
    ResponseState::Active,
    ResponseState::ApplyPartial,
    ResponseState::Expiring,
    ResponseState::RollingBack,
    ResponseState::RollbackPartial,
    ResponseState::Cancelled,
    ResponseState::Expired,
    ResponseState::Failed,
    ResponseState::Lifted,
];

#[test]
fn response_transition_matrix_contains_only_the_specified_edges() {
    let legal = [
        (ResponseState::Planned, ResponseState::AwaitingApproval),
        (ResponseState::Planned, ResponseState::Applying),
        (ResponseState::Planned, ResponseState::Cancelled),
        (ResponseState::Planned, ResponseState::Expired),
        (ResponseState::Planned, ResponseState::Failed),
        (ResponseState::AwaitingApproval, ResponseState::Applying),
        (ResponseState::AwaitingApproval, ResponseState::Cancelled),
        (ResponseState::AwaitingApproval, ResponseState::Expired),
        (ResponseState::AwaitingApproval, ResponseState::Failed),
        (ResponseState::Applying, ResponseState::Active),
        (ResponseState::Applying, ResponseState::ApplyPartial),
        (ResponseState::Applying, ResponseState::Failed),
        (ResponseState::ApplyPartial, ResponseState::RollingBack),
        (ResponseState::Active, ResponseState::Expiring),
        (ResponseState::Active, ResponseState::RollingBack),
        (ResponseState::Expiring, ResponseState::RollingBack),
        (ResponseState::RollingBack, ResponseState::Lifted),
        (ResponseState::RollingBack, ResponseState::RollbackPartial),
        (ResponseState::RollbackPartial, ResponseState::RollingBack),
    ];

    for from in STATES {
        for to in STATES {
            assert_eq!(
                is_legal_response_transition(from, to),
                legal.contains(&(from, to)),
                "unexpected transition result for {from:?} -> {to:?}"
            );
        }
    }
}

#[test]
fn permanent_revocation_is_not_a_reversible_effect_kind() {
    let reversible = [
        ResponseEffectKind::EscalateAlert,
        ResponseEffectKind::ThrottleSession,
        ResponseEffectKind::RestrictEgress,
        ResponseEffectKind::SuspendSession,
        ResponseEffectKind::SuspendCapabilitySet,
        ResponseEffectKind::FreezeIssuance,
    ];
    for kind in reversible {
        let encoded = serde_json::to_string(&kind)
            .unwrap_or_else(|error| panic!("effect kind serialization failed: {error}"));
        assert!(!encoded.contains("revocation"));
    }
    assert!(serde_json::from_str::<ResponseEffectKind>("\"permanent_revocation\"").is_err());
}

#[test]
fn response_targets_and_mutation_records_reject_unknown_fields() {
    let target = ResponseTarget::Tenant {
        tenant_id: TenantId::new("tenant-response")
            .unwrap_or_else(|error| panic!("invalid tenant id: {error}")),
    };
    let mut target_value = serde_json::to_value(target)
        .unwrap_or_else(|error| panic!("target serialization failed: {error}"));
    target_value["unknown"] = serde_json::json!(true);
    assert!(serde_json::from_value::<ResponseTarget>(target_value).is_err());

    let mutation = ResponseMutationRecord::Requested(ResponseRequestedRecord {
        transition_id: RecordId::new("response-request")
            .unwrap_or_else(|error| panic!("invalid transition id: {error}")),
        generation: 0,
        occurred_at_unix_ms: 100,
    });
    let mut mutation_value = serde_json::to_value(mutation)
        .unwrap_or_else(|error| panic!("mutation serialization failed: {error}"));
    mutation_value["unknown"] = serde_json::json!(true);
    assert!(serde_json::from_value::<ResponseMutationRecord>(mutation_value).is_err());
}
