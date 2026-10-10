use super::*;

#[test]
fn session_target_derivation_matches_the_enforcement_guard() {
    let context = SecurityInvocationContextV1::new(
        tenant(),
        session(),
        PrincipalId::new("principal-a").unwrap_or_else(|error| panic!("principal: {error}")),
        IsolationEpochId::new("epoch-a").unwrap_or_else(|error| panic!("isolation epoch: {error}")),
        LineageId::new("lineage-a").unwrap_or_else(|error| panic!("lineage: {error}")),
        1,
    );
    let guard_target = containment_target(
        &context,
        ContainmentTargetKind::Session,
        context.session_id().as_str(),
    )
    .unwrap_or_else(|error| panic!("guard target: {error}"));
    let effect_target = session_containment_target(context.tenant_id(), context.session_id())
        .unwrap_or_else(|error| panic!("effect target: {error}"));
    assert_eq!(effect_target, guard_target);

    let mut legacy_preimage = b"chio.security.containment-target.v1\0".to_vec();
    legacy_preimage.extend_from_slice(b"session");
    legacy_preimage.push(0);
    legacy_preimage.extend_from_slice(context.session_id().as_str().as_bytes());
    let legacy_digest = chio_core::sha256(&legacy_preimage);
    let mut legacy_hex = String::with_capacity(64);
    for byte in legacy_digest.as_bytes() {
        legacy_hex.push_str(format!("{byte:02x}").as_str());
    }
    let legacy_target = TenantScopedId {
        tenant_id: context.tenant_id().clone(),
        id: RecordId::new(format!("session-{legacy_hex}"))
            .unwrap_or_else(|error| panic!("legacy target id: {error}")),
    };
    assert_eq!(effect_target, legacy_target);
}
