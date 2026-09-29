use super::*;

#[test]
fn malformed_or_rebound_session_effects_fail_before_mutation() {
    let store = Arc::new(RecordingOverlayStore::default());
    let port = port(Arc::clone(&store));
    let target = session_containment_target(&tenant(), &session())
        .unwrap_or_else(|error| panic!("target: {error}"));
    let base = session_overlay_version_hash(store.as_ref(), &target)
        .unwrap_or_else(|error| panic!("base: {error}"));

    let mut zero_rank = request(EffectOperation::Apply, base, 0);
    let zero_error = require_error(port.execute(&zero_rank));
    assert_eq!(zero_error.kind(), PortErrorKind::InvalidData);

    let stale = request(EffectOperation::Apply, Digest32::new([71; 32]), 2);
    let stale_error = require_error(port.execute(&stale));
    assert_eq!(stale_error.kind(), PortErrorKind::Conflict);

    zero_rank = request(EffectOperation::Apply, base, 2);
    zero_rank.contribution_hash = Digest32::new([99; 32]);
    let hash_error = require_error(port.execute(&zero_rank));
    assert_eq!(hash_error.kind(), PortErrorKind::IntegrityFailure);

    let mut noncanonical = request(EffectOperation::Apply, base, 2);
    noncanonical.canonical_contribution = CanonicalBody::new(b"{ \"posture_rank\": 2 }".to_vec())
        .unwrap_or_else(|error| panic!("noncanonical contribution: {error}"));
    noncanonical.contribution_hash = Digest32::new(
        *chio_core::sha256(noncanonical.canonical_contribution.as_bytes()).as_bytes(),
    );
    let canonical_error = require_error(port.execute(&noncanonical));
    assert_eq!(canonical_error.kind(), PortErrorKind::IntegrityFailure);

    let mut unbound_command = request(EffectOperation::Apply, base, 2);
    unbound_command.idempotency_key =
        RecordId::new("unbound-command").unwrap_or_else(|error| panic!("unbound command: {error}"));
    let command_error = require_error(port.execute(&unbound_command));
    assert_eq!(command_error.kind(), PortErrorKind::InvalidData);

    let mut wrong_target = request(EffectOperation::Apply, base, 2);
    wrong_target.target = ResponseTarget::Lineage {
        lineage_id: LineageId::new("lineage-a").unwrap_or_else(|error| panic!("lineage: {error}")),
    };
    let target_error = require_error(port.execute(&wrong_target));
    assert_eq!(target_error.kind(), PortErrorKind::InvalidData);
    assert_eq!(store.counts().0, 0);
    assert_eq!(store.counts().1, 0);
}
