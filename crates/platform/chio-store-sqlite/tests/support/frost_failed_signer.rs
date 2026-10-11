use super::*;
use chio_store_sqlite::FrostStoreError;

#[test]
fn failed_ceremony_refuses_cached_signer_commitment_and_share(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = StoreFixture::new();
    let (authority, frost) = fixture.open();
    let completion = complete_ceremony(&authority, &frost);
    let roster = signed_roster(&completion);
    let epoch = signed_epoch(&roster);
    let fixed_epoch = FixedEpoch(epoch.clone());
    let trust = trust_store();
    let active = resolve_active_roster_for_execution(
        &roster.scope_id,
        &Resolver(roster.clone()),
        &fixed_epoch,
        &trust,
        4000,
    )?;
    let body = authorization_body(&roster, "failed-ceremony", 7);
    let slot = MutableSlotAnchor::new(body.clone());
    let request = FrostSignerSessionRequest {
        body: &body,
        active_roster: &active,
        epoch_anchor: &fixed_epoch,
        slot_anchor: &slot,
        artifact_trust: &trust,
        ceremony_id: &completion.ceremony_id,
        participant_id: "operator-1",
        coordinator_id: "coordinator-1",
    };
    let fence = authority.mutation_fence();
    let mut rng = ChaCha20Rng::from_seed([0xe1; 32]);
    frost.prepare_signer_session(&request, &custody(), &mut rng, &fence, 4001)?;
    let commitment = frost.publish_signer_commitment(&request, &custody(), &fence, 4002)?;
    let package = signing_package(
        &commitment.commitment_bytes,
        &commitment.signer_identifier,
        &body.signing_bytes()?,
    );
    frost.prepare_signer_share(&request, &package, &custody(), &fence, 4003)?;
    assert!(matches!(
        frost.accept_round2_package(
            &completion.config,
            &custody(),
            &completion.conflicting_envelope,
            &fence,
            4004
        ),
        Err(FrostStoreError::CeremonyFailed)
    ));
    assert!(matches!(
        frost.prepare_signer_session(&request, &custody(), &mut rng, &fence, 4005),
        Err(FrostStoreError::CeremonyFailed)
    ));
    assert!(matches!(
        frost.publish_signer_commitment(&request, &custody(), &fence, 4005),
        Err(FrostStoreError::CeremonyFailed)
    ));
    assert!(matches!(
        frost.prepare_signer_share(&request, &package, &custody(), &fence, 4005),
        Err(FrostStoreError::CeremonyFailed)
    ));
    assert!(matches!(
        frost.publish_signer_share(&request, &custody(), &fence, 4005),
        Err(FrostStoreError::CeremonyFailed)
    ));
    Ok(())
}
