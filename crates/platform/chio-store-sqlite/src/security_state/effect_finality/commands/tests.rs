use chio_security_types::ports::{
    capability_set_suspension_installed_version_hash, capability_set_suspension_version_hash,
    response_affected_set_hash, validate_capability_set_suspension_snapshot, CanonicalBody,
    CapabilitySetSuspensionCommand, CapabilitySetSuspensionContribution,
    CapabilitySetSuspensionContributions, CapabilitySetSuspensionKey,
    CapabilitySetSuspensionSnapshot, CapabilitySetSuspensionSpec, LeaseOwnerId, RecordIdSet,
};

use super::*;

#[test]
fn authenticated_snapshot_over_two_mib_keeps_its_existing_canonical_reader_contract() {
    let tenant =
        TenantId::new("large-history-tenant").unwrap_or_else(|error| panic!("tenant: {error}"));
    let ids = RecordIdSet::new(
        (0..4096)
            .map(|index| {
                RecordId::new(format!("{index:04}-{}", "x".repeat(230)))
                    .unwrap_or_else(|error| panic!("bounded full-width ID: {error}"))
            })
            .collect(),
    )
    .unwrap_or_else(|error| panic!("bounded affected set: {error}"));
    assert_eq!(ids.as_slice().len(), 4096);
    let spec_bytes = canonical_json_bytes(&CapabilitySetSuspensionSpec {
        affected_ids: ids.clone(),
    })
    .unwrap_or_else(|error| panic!("canonical contribution: {error}"));
    let contribution_hash = Digest32::new(body_hash(&spec_bytes));
    assert!(
        spec_bytes.len() <= 1_048_576,
        "the existing contribution body bound is unchanged"
    );
    let key = CapabilitySetSuspensionKey {
        tenant_id: tenant.clone(),
        affected_set_hash: response_affected_set_hash(&tenant, &ids)
            .unwrap_or_else(|error| panic!("affected-set hash: {error}")),
    };
    let contribution = |index| CapabilitySetSuspensionContribution {
        action_id: ActionId::new(format!("large-history-action-{index}"))
            .unwrap_or_else(|error| panic!("action: {error}")),
        effect_id: EffectId::new(format!("large-history-effect-{index}"))
            .unwrap_or_else(|error| panic!("effect: {error}")),
        affected_ids: ids.clone(),
        contribution_hash,
        expires_at_unix_ms: 10_000,
    };
    let removed = contribution(3);
    let snapshot = CapabilitySetSuspensionSnapshot {
        key: key.clone(),
        generation: 5,
        contributions: CapabilitySetSuspensionContributions::new(
            (0..3).map(contribution).collect(),
        )
        .unwrap_or_else(|error| panic!("three valid contributions: {error}")),
        highest_fencing_token: 1,
    };
    validate_capability_set_suspension_snapshot(&snapshot, &key)
        .unwrap_or_else(|error| panic!("owning snapshot validation: {error}"));
    let snapshot_bytes = canonical_json_bytes(&snapshot)
        .unwrap_or_else(|error| panic!("canonical snapshot: {error}"));
    assert!(snapshot_bytes.len() > 2 * 1024 * 1024);
    assert!(snapshot_bytes.len() < MAX_AUTHENTICATED_COMMAND_BYTES);
    let decoded: CapabilitySetSuspensionSnapshot =
        chio_core::canonical::UntrustedJsonText::from_wire(
            &snapshot_bytes,
            MAX_AUTHENTICATED_COMMAND_BYTES,
        )
        .and_then(|input| input.decode_signed())
        .unwrap_or_else(|error| panic!("existing authenticated canonical reader: {error}"));
    assert_eq!(decoded, snapshot);
    let command = CapabilitySetSuspensionCommand {
        request: EffectRequest {
            tenant_id: tenant,
            action_id: removed.action_id.clone(),
            plan_hash: Digest32::new([8; 32]),
            effect_id: removed.effect_id.clone(),
            effect_kind: ResponseEffectKind::SuspendCapabilitySet,
            target: ResponseTarget::CapabilitySet {
                affected_set_hash: key.affected_set_hash,
            },
            plan_expires_at_unix_ms: removed.expires_at_unix_ms,
            operation: EffectOperation::Remove,
            idempotency_key: RecordId::new("response_effect_command:large-history-remove")
                .unwrap_or_else(|error| panic!("command: {error}")),
            expected_version_hash: capability_set_suspension_installed_version_hash(&key, &removed)
                .unwrap_or_else(|error| panic!("original installed hash: {error}")),
            scheduler_lease_owner_id: LeaseOwnerId::new("large-history-owner")
                .unwrap_or_else(|error| panic!("lease owner: {error}")),
            scheduler_fencing_token: 1,
            canonical_contribution: CanonicalBody::new(spec_bytes)
                .unwrap_or_else(|error| panic!("contribution body: {error}")),
            contribution_hash,
        },
        result: EffectResult {
            effect_id: removed.effect_id,
            applied: false,
            resulting_version_hash: capability_set_suspension_version_hash(&snapshot)
                .unwrap_or_else(|error| panic!("removed snapshot hash: {error}")),
        },
        resulting_snapshot: snapshot,
    };
    crate::security_state::capability_set_suspension::validate_stored_command(&command)
        .unwrap_or_else(|error| panic!("owning authenticated stored-command validation: {error}"));
    let expected_hash = Digest32::new(body_hash(&snapshot_bytes));
    let projected = project(command.request, command.result, Some(snapshot_bytes))
        .unwrap_or_else(|error| panic!("lossless historical projection: {error}"));
    assert_eq!(projected.snapshot_hash, Some(expected_hash));
    let marker = Marker::from_command(&projected)
        .unwrap_or_else(|error| panic!("bounded first-removal marker: {error}"));
    assert_eq!(marker.snapshot_body_hash, Some(expected_hash));
    assert!(
        canonical_json_bytes(&marker)
            .unwrap_or_else(|error| panic!("marker canonical bytes: {error}"))
            .len()
            <= MAX_MARKER_BYTES
    );
}
