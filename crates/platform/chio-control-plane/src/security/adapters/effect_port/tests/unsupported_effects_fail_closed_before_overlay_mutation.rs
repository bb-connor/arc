use super::*;


#[test]
fn unsupported_effects_fail_closed_before_overlay_mutation() {
    let store = Arc::new(RecordingOverlayStore::default());
    let port = port(Arc::clone(&store));
    let base = Digest32::new([0; 32]);
    for (kind, target) in [
        (
            ResponseEffectKind::EscalateAlert,
            ResponseTarget::Tenant {
                tenant_id: tenant(),
            },
        ),
        (
            ResponseEffectKind::ThrottleSession,
            ResponseTarget::Session {
                session_id: session(),
            },
        ),
        (
            ResponseEffectKind::RestrictEgress,
            ResponseTarget::Session {
                session_id: session(),
            },
        ),
        (
            ResponseEffectKind::SuspendCapabilitySet,
            ResponseTarget::CapabilitySet {
                affected_set_hash: Digest32::new([3; 32]),
            },
        ),
        (
            ResponseEffectKind::FreezeIssuance,
            ResponseTarget::Lineage {
                lineage_id: LineageId::new("lineage-a")
                    .unwrap_or_else(|error| panic!("lineage: {error}")),
            },
        ),
    ] {
        let mut unsupported = request(EffectOperation::Apply, base, 1);
        unsupported.effect_kind = kind;
        unsupported.target = target;
        let error = require_error(port.execute(&unsupported));
        assert_eq!(error.kind(), PortErrorKind::Unavailable);
    }
    assert_eq!(store.counts().0, 0);
    assert_eq!(store.counts().1, 0);
}
