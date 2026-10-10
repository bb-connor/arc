use chio_core_types::Keypair;
use chio_federation_authority::{
    advance_frost_ceremony, begin_frost_ceremony, complete_frost_ceremony, FrostCeremonyConfig,
    FrostCeremonyError, FrostCeremonyParticipant, FrostCeremonySecret, FrostCeremonySecretKind,
    FrostDkgRound,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

#[test]
fn sealed_round_two_opens_only_for_its_recipient() -> Result<(), Box<dyn std::error::Error>> {
    let fixtures = fixtures();
    let mut round1 = Vec::new();
    let mut secrets = Vec::new();
    for (index, fixture) in fixtures.iter().enumerate() {
        let mut rng = ChaCha20Rng::from_seed([index as u8 + 41; 32]);
        let transition = begin_frost_ceremony(
            &fixture.config,
            &fixture.transport_key,
            &test_sealing_key(&fixture.config),
            &mut rng,
        )?;
        round1.push(transition.package);
        secrets.push(transition.secret);
    }
    let transition = advance_frost_ceremony(
        &fixtures[0].config,
        &fixtures[0].transport_key,
        secrets.remove(0),
        &round1,
    )?;
    let envelope = &transition.packages[0];
    let bytes = chio_core_types::canonical::canonical_json_bytes(envelope)?;
    let restored = chio_federation_authority::SealedFrostRound2Package::from_wire(&bytes)?;
    assert_eq!(restored, *envelope);
    let opened = envelope.open(&fixtures[1].config, &test_sealing_key(&fixtures[1].config))?;
    assert!(!format!("{transition:?}{opened:?}").contains(&hex::encode(opened.secret_bytes())));
    assert!(!String::from_utf8(bytes)?.contains(&hex::encode(opened.secret_bytes())));
    assert!(matches!(
        envelope.open(&fixtures[2].config, &test_sealing_key(&fixtures[2].config)),
        Err(FrostCeremonyError::Sealing(
            chio_federation_authority::FrostSealingError::Recipient
        ))
    ));
    Ok(())
}

struct ParticipantFixture {
    config: FrostCeremonyConfig,
    transport_key: Keypair,
}

fn fixtures() -> Vec<ParticipantFixture> {
    let transport_keys = [
        Keypair::from_seed(&[0x11; 32]),
        Keypair::from_seed(&[0x22; 32]),
        Keypair::from_seed(&[0x33; 32]),
    ];
    let participants = transport_keys
        .iter()
        .enumerate()
        .map(|(index, key)| FrostCeremonyParticipant {
            participant_id: format!("operator-{}", index + 1),
            transport_key_id: format!("operator-{}.dkg.v1", index + 1),
            transport_public_key: key.public_key(),
            sealing_key_id: format!("operator-{}.sealing.v1", index + 1),
            sealing_public_key: test_sealing_key_for(index)
                .public_key()
                .unwrap_or_else(|e| panic!("fixture sealing key: {e}")),
        })
        .collect::<Vec<_>>();

    transport_keys
        .into_iter()
        .enumerate()
        .map(|(index, transport_key)| ParticipantFixture {
            config: FrostCeremonyConfig {
                scope_id: "treaty.atlantic.v1".to_string(),
                key_epoch: 2,
                threshold: 2,
                predecessor_roster_digest: Some("44".repeat(32)),
                participants: participants.clone(),
                local_participant_id: format!("operator-{}", index + 1),
            },
            transport_key,
        })
        .collect()
}

#[test]
fn frost_ceremony_resumes_the_exact_upstream_state_after_each_round() {
    let fixtures = fixtures();
    let mut round1 = Vec::new();
    let mut round1_custody = Vec::new();
    for (index, fixture) in fixtures.iter().enumerate() {
        let mut rng = ChaCha20Rng::from_seed([index as u8 + 1; 32]);
        let transition = begin_frost_ceremony(
            &fixture.config,
            &fixture.transport_key,
            &test_sealing_key(&fixture.config),
            &mut rng,
        )
        .unwrap_or_else(|error| panic!("round one must start: {error}"));
        assert_eq!(transition.package.round(), FrostDkgRound::Round1);
        round1.push(transition.package);
        round1_custody.push(transition.secret.into_custody_bytes());
    }

    let mut round2 = Vec::new();
    let mut round2_custody = Vec::new();
    for ((fixture, custody_bytes), index) in fixtures.iter().zip(round1_custody).zip(0_u8..) {
        let recovered =
            FrostCeremonySecret::from_custody_bytes(FrostCeremonySecretKind::Round1, custody_bytes)
                .unwrap_or_else(|error| panic!("round one custody must reopen: {error}"));
        let transition =
            advance_frost_ceremony(&fixture.config, &fixture.transport_key, recovered, &round1)
                .unwrap_or_else(|error| panic!("round two must advance: {error}"));
        assert_eq!(transition.packages.len(), fixtures.len() - 1);
        assert!(transition
            .packages
            .iter()
            .all(|package| package.round() == FrostDkgRound::Round2));
        round2.extend(transition.packages);
        round2_custody.push((transition.secret.into_custody_bytes(), index));
    }

    let mut transcript_digests = Vec::new();
    let mut group_keys = Vec::new();
    for (fixture, (custody_bytes, _index)) in fixtures.iter().zip(round2_custody) {
        let recovered =
            FrostCeremonySecret::from_custody_bytes(FrostCeremonySecretKind::Round2, custody_bytes)
                .unwrap_or_else(|error| panic!("round two custody must reopen: {error}"));
        let completion = complete_frost_ceremony(
            &fixture.config,
            recovered,
            &round1,
            &round2,
            opened_packages(&fixture.config, &round2),
        )
        .unwrap_or_else(|error| panic!("ceremony must complete: {error}"));
        assert_eq!(
            completion.key_package.kind(),
            FrostCeremonySecretKind::KeyPackage
        );
        transcript_digests.push(completion.transcript_digest);
        group_keys.push(completion.group_public_key);
    }
    assert!(transcript_digests.windows(2).all(|pair| pair[0] == pair[1]));
    assert!(group_keys.windows(2).all(|pair| pair[0] == pair[1]));
}

#[test]
fn frost_ceremony_rejects_participant_drift_duplicate_packages_and_tampering() {
    let fixtures = fixtures();
    let mut rng = ChaCha20Rng::from_seed([7; 32]);
    let first = begin_frost_ceremony(
        &fixtures[0].config,
        &fixtures[0].transport_key,
        &test_sealing_key(&fixtures[0].config),
        &mut rng,
    )
    .unwrap_or_else(|error| panic!("fixture must start: {error}"));

    let mut changed = fixtures[0].config.clone();
    changed.participants.swap(0, 1);
    let recovered = FrostCeremonySecret::from_custody_bytes(
        FrostCeremonySecretKind::Round1,
        first.secret.into_custody_bytes(),
    )
    .unwrap_or_else(|error| panic!("fixture secret must reopen: {error}"));
    assert!(matches!(
        advance_frost_ceremony(
            &changed,
            &fixtures[0].transport_key,
            recovered,
            std::slice::from_ref(&first.package),
        ),
        Err(FrostCeremonyError::InvalidConfig(_)) | Err(FrostCeremonyError::Transcript(_))
    ));

    let mut round1 = Vec::new();
    let mut local_secret = None;
    for (index, fixture) in fixtures.iter().enumerate() {
        let mut rng = ChaCha20Rng::from_seed([index as u8 + 9; 32]);
        let transition = begin_frost_ceremony(
            &fixture.config,
            &fixture.transport_key,
            &test_sealing_key(&fixture.config),
            &mut rng,
        )
        .unwrap_or_else(|error| panic!("fixture must start: {error}"));
        if index == 0 {
            local_secret = Some(transition.secret);
        }
        round1.push(transition.package);
    }
    round1.push(round1[1].clone());
    assert!(matches!(
        advance_frost_ceremony(
            &fixtures[0].config,
            &fixtures[0].transport_key,
            local_secret.unwrap_or_else(|| panic!("local secret must exist")),
            &round1,
        ),
        Err(FrostCeremonyError::DuplicatePackage { .. })
    ));

    let mut rng = ChaCha20Rng::from_seed([19; 32]);
    let local = begin_frost_ceremony(
        &fixtures[0].config,
        &fixtures[0].transport_key,
        &test_sealing_key(&fixtures[0].config),
        &mut rng,
    )
    .unwrap_or_else(|error| panic!("fixture must restart: {error}"));
    let mut packages = Vec::new();
    for (index, fixture) in fixtures.iter().enumerate() {
        if index == 0 {
            packages.push(local.package.clone());
            continue;
        }
        let mut rng = ChaCha20Rng::from_seed([index as u8 + 20; 32]);
        packages.push(
            begin_frost_ceremony(
                &fixture.config,
                &fixture.transport_key,
                &test_sealing_key(&fixture.config),
                &mut rng,
            )
            .unwrap_or_else(|error| panic!("peer must start: {error}"))
            .package,
        );
    }
    let mut tampered = serde_json::to_value(&packages[1])
        .unwrap_or_else(|error| panic!("package must serialize: {error}"));
    tampered["packageDigest"] = serde_json::Value::String("00".repeat(32));
    packages[1] = serde_json::from_value(tampered)
        .unwrap_or_else(|error| panic!("tampered package must decode: {error}"));
    assert!(matches!(
        advance_frost_ceremony(
            &fixtures[0].config,
            &fixtures[0].transport_key,
            local.secret,
            &packages,
        ),
        Err(FrostCeremonyError::PackageAuthentication {
            detail: "package digest does not match",
            ..
        })
    ));
}

fn test_sealing_key_for(index: usize) -> chio_federation_authority::FrostSealingKey {
    let byte = u8::try_from(index).unwrap_or_else(|_| panic!("fixture index"));
    chio_federation_authority::FrostSealingKey::from_custody_bytes(zeroize::Zeroizing::new(
        [0x80 + byte; 32],
    ))
}
fn test_sealing_key(config: &FrostCeremonyConfig) -> chio_federation_authority::FrostSealingKey {
    let index = config
        .participants
        .iter()
        .position(|p| p.participant_id == config.local_participant_id)
        .unwrap_or_else(|| panic!("local fixture participant"));
    test_sealing_key_for(index)
}
fn opened_packages(
    config: &FrostCeremonyConfig,
    packages: &[chio_federation_authority::SealedFrostRound2Package],
) -> Vec<chio_federation_authority::FrostRound2Package> {
    packages
        .iter()
        .filter(|p| p.recipient_participant_id() == config.local_participant_id)
        .map(|p| {
            p.open(config, &test_sealing_key(config))
                .unwrap_or_else(|e| panic!("open fixture: {e}"))
        })
        .collect()
}

// Compile and exercise the exact fuzz entry without compiling unrelated fuzz
// owners. This crate is an unpublished workspace component.
#[path = "../../../../fuzz/src/entries/frost_round2_envelope.rs"]
mod fuzz_entry;

#[test]
fn sealed_fuzz_entry_handles_pinned_seeds_and_bounded_mutations(
) -> Result<(), Box<dyn std::error::Error>> {
    use rand_core::RngCore;
    let seeds: Vec<serde_json::Value> =
        serde_json::from_slice(include_bytes!("fixtures/frost-round2-sealed-v1.json"))?;
    let mut rng = ChaCha20Rng::from_seed([0x91; 32]);
    for seed in &seeds {
        let wire = chio_core_types::canonical::canonical_json_bytes(seed)?;
        fuzz_entry::frost_round2_envelope(&wire);
        for _ in 0..100 {
            let mut changed = wire.clone();
            let index = rng.next_u64() as usize % changed.len();
            changed[index] ^= 1 << (rng.next_u32() % 8);
            fuzz_entry::frost_round2_envelope(&changed);
        }
    }
    fuzz_entry::frost_round2_envelope(&[b' '; 32769]);
    Ok(())
}
