use chio_security_types::ports::{
    ActionId, CanonicalBody, DestinationId, Digest32, EffectId, EffectOperation, EffectRequest,
    EffectResult, EgressDestinationSet, EgressRestrictionApplyRequest, EgressRestrictionCommand,
    EgressRestrictionContribution, EgressRestrictionDecision, EgressRestrictionRemoveRequest,
    EgressRestrictionSessionKey, EgressRestrictionSnapshot, RecordId, SessionId, TenantId,
};
use chio_security_types::{ResponseEffectKind, ResponseTarget};

fn tenant() -> TenantId {
    TenantId::new("tenant-a").unwrap_or_else(|error| panic!("tenant: {error}"))
}

fn session() -> SessionId {
    SessionId::new("session-a").unwrap_or_else(|error| panic!("session: {error}"))
}

fn destination(value: &str) -> DestinationId {
    DestinationId::new(value).unwrap_or_else(|error| panic!("destination: {error}"))
}

#[test]
fn destination_set_requires_nonempty_strict_canonical_order() {
    let canonical =
        EgressDestinationSet::new(vec![destination("server-a"), destination("server-b")])
            .unwrap_or_else(|error| panic!("canonical destinations: {error}"));
    assert_eq!(canonical.len(), 2);

    assert!(EgressDestinationSet::new(Vec::new()).is_err());
    assert!(
        EgressDestinationSet::new(vec![destination("server-b"), destination("server-a")]).is_err()
    );
    assert!(
        EgressDestinationSet::new(vec![destination("server-a"), destination("server-a")]).is_err()
    );

    let encoded = serde_json::to_vec(&canonical)
        .unwrap_or_else(|error| panic!("serialize destinations: {error}"));
    let decoded: EgressDestinationSet = serde_json::from_slice(&encoded)
        .unwrap_or_else(|error| panic!("deserialize destinations: {error}"));
    assert_eq!(decoded, canonical);
    assert!(serde_json::from_slice::<EgressDestinationSet>(br#"["server-b","server-a"]"#).is_err());
}

#[test]
fn egress_overlay_contracts_bind_session_effect_ttl_and_fence() {
    let key = EgressRestrictionSessionKey {
        tenant_id: tenant(),
        session_id: session(),
    };
    let contribution = EgressRestrictionContribution {
        effect_id: EffectId::new("effect-a").unwrap_or_else(|error| panic!("effect: {error}")),
        destinations: EgressDestinationSet::new(vec![destination("server-a")])
            .unwrap_or_else(|error| panic!("destinations: {error}")),
        contribution_hash: Digest32::new([4; 32]),
        expires_at_unix_ms: 90_000,
    };
    let effect_request = EffectRequest {
        tenant_id: key.tenant_id.clone(),
        action_id: ActionId::new("action-a").unwrap_or_else(|error| panic!("action: {error}")),
        plan_hash: Digest32::new([5; 32]),
        effect_id: contribution.effect_id.clone(),
        effect_kind: ResponseEffectKind::RestrictEgress,
        target: ResponseTarget::Session {
            session_id: key.session_id.clone(),
        },
        plan_expires_at_unix_ms: contribution.expires_at_unix_ms,
        operation: EffectOperation::Apply,
        idempotency_key: RecordId::new("response_effect_command:apply")
            .unwrap_or_else(|error| panic!("idempotency key: {error}")),
        expected_version_hash: Digest32::new([6; 32]),
        scheduler_lease_owner_id: chio_security_types::ports::LeaseOwnerId::new(
            "egress-contract-worker",
        )
        .unwrap_or_else(|error| panic!("lease owner: {error}")),
        scheduler_fencing_token: 11,
        canonical_contribution: CanonicalBody::new(b"{\"destinations\":[\"server-a\"]}".to_vec())
            .unwrap_or_else(|error| panic!("canonical contribution: {error}")),
        contribution_hash: contribution.contribution_hash,
    };
    let apply = EgressRestrictionApplyRequest {
        key: key.clone(),
        action_id: effect_request.action_id.clone(),
        contribution: contribution.clone(),
        expected_generation: 7,
        scheduler_fencing_token: 11,
        command: EgressRestrictionCommand {
            request: effect_request.clone(),
            result: EffectResult {
                effect_id: contribution.effect_id.clone(),
                resulting_version_hash: Digest32::new([7; 32]),
                applied: true,
            },
        },
    };
    let mut remove_effect_request = effect_request;
    remove_effect_request.operation = EffectOperation::Remove;
    remove_effect_request.idempotency_key = RecordId::new("response_effect_command:remove")
        .unwrap_or_else(|error| panic!("remove idempotency key: {error}"));
    remove_effect_request.scheduler_fencing_token = 12;
    let remove = EgressRestrictionRemoveRequest {
        key: key.clone(),
        action_id: apply.action_id.clone(),
        effect_id: contribution.effect_id.clone(),
        expected_generation: 8,
        scheduler_fencing_token: 12,
        command: EgressRestrictionCommand {
            request: remove_effect_request,
            result: EffectResult {
                effect_id: contribution.effect_id.clone(),
                resulting_version_hash: Digest32::new([8; 32]),
                applied: false,
            },
        },
    };
    let snapshot = EgressRestrictionSnapshot {
        key: key.clone(),
        generation: 8,
        contributions: chio_security_types::ports::EgressRestrictionContributions::new(vec![
            contribution.clone(),
        ])
        .unwrap_or_else(|error| panic!("contributions: {error}")),
        denied_destinations: chio_security_types::ports::EgressDeniedDestinations::new(vec![
            destination("server-a"),
        ])
        .unwrap_or_else(|error| panic!("denied destinations: {error}")),
        highest_fencing_token: 11,
    };
    let decision = EgressRestrictionDecision {
        key,
        destination_id: destination("server-a"),
        denied: true,
        active_effect_ids: chio_security_types::ports::EgressRestrictionEffectIds::new(vec![
            contribution.effect_id,
        ])
        .unwrap_or_else(|error| panic!("effect ids: {error}")),
        generation: snapshot.generation,
    };

    assert_eq!(
        apply.contribution.destinations.as_slice(),
        &[destination("server-a")]
    );
    assert_eq!(remove.effect_id.as_str(), "effect-a");
    assert_eq!(
        snapshot.denied_destinations.as_slice(),
        &[destination("server-a")]
    );
    assert!(decision.denied);
}
