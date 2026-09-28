use chio_core_types::Keypair;
use chio_federation_authority::{
    advance_frost_ceremony, begin_frost_ceremony, complete_frost_ceremony, FrostCeremonyConfig,
    FrostCeremonyError, FrostCeremonyParticipant, FrostCeremonySecret, FrostCeremonySecretKind,
    FrostDkgRound,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

#[test]
fn round_two_custody_restores_only_the_bound_outbound_package(
) -> Result<(), Box<dyn std::error::Error>> {
    use chio_federation_authority::{FrostRound1Package, FrostRound2Package};
    let fixtures = fixtures();
    let mut round1 = Vec::new();
    let mut secrets = Vec::new();
    for (index, fixture) in fixtures.iter().enumerate() {
        let mut rng = ChaCha20Rng::from_seed([index as u8 + 41; 32]);
        let transition = begin_frost_ceremony(&fixture.config, &fixture.transport_key, &mut rng)?;
        let bytes = serde_json::to_vec(&transition.package)?;
        assert_eq!(
            serde_json::from_slice::<FrostRound1Package>(&bytes)?,
            transition.package
        );
        let mut wrong_round = serde_json::to_value(&transition.package)?;
        wrong_round["round"] = serde_json::json!("round2");
        assert!(serde_json::from_value::<FrostRound1Package>(wrong_round).is_err());
        round1.push(transition.package);
        secrets.push(transition.secret);
    }
    let transition = advance_frost_ceremony(
        &fixtures[0].config,
        &fixtures[0].transport_key,
        secrets.remove(0),
        &round1,
    )?;
    let package = &transition.packages[0];
    let restored = FrostRound2Package::from_custody(
        &fixtures[0].config,
        package.metadata(),
        package.secret_bytes(),
    )?;
    assert_eq!(&restored, package);
    let debug = format!("{transition:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains(&hex::encode(package.secret_bytes())));
    assert!(!serde_json::to_string(&package.metadata())?.contains("secretBytes"));

    let mut corrupt = package.secret_bytes();
    corrupt[0] ^= 1;
    assert!(matches!(
        FrostRound2Package::from_custody(&fixtures[0].config, package.metadata(), corrupt),
        Err(FrostCeremonyError::PackageAuthentication {
            detail: "package digest does not match",
            ..
        })
    ));
    assert!(matches!(
        FrostRound2Package::from_custody(
            &fixtures[1].config,
            package.metadata(),
            package.secret_bytes()
        ),
        Err(FrostCeremonyError::PackageAuthentication {
            detail: "custody package belongs to another participant",
            ..
        })
    ));
    for (field, replacement, expected) in [
        (
            "ceremonyId",
            serde_json::json!("untrusted"),
            "package ceremony binding does not match",
        ),
        (
            "keyEpoch",
            serde_json::json!(99),
            "package ceremony binding does not match",
        ),
        (
            "round",
            serde_json::json!("round1"),
            "package ceremony binding does not match",
        ),
        (
            "recipientParticipantId",
            serde_json::json!(fixtures[0].config.local_participant_id),
            "round-two recipient is invalid",
        ),
        (
            "transportSignature",
            serde_json::json!("00".repeat(64)),
            "transport signature does not verify",
        ),
    ] {
        let mut metadata = serde_json::to_value(package.metadata())?;
        metadata[field] = replacement;
        let error = match FrostRound2Package::from_custody(
            &fixtures[0].config,
            serde_json::from_value(metadata)?,
            package.secret_bytes(),
        ) {
            Err(error) => error,
            Ok(_) => panic!("modified custody binding was accepted"),
        };
        assert!(
            matches!(error, FrostCeremonyError::PackageAuthentication { detail, .. } if detail == expected)
        );
    }
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
        let transition = begin_frost_ceremony(&fixture.config, &fixture.transport_key, &mut rng)
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
        let completion = complete_frost_ceremony(&fixture.config, recovered, &round1, &round2)
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
    let first = begin_frost_ceremony(&fixtures[0].config, &fixtures[0].transport_key, &mut rng)
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
        let transition = begin_frost_ceremony(&fixture.config, &fixture.transport_key, &mut rng)
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
    let local = begin_frost_ceremony(&fixtures[0].config, &fixtures[0].transport_key, &mut rng)
        .unwrap_or_else(|error| panic!("fixture must restart: {error}"));
    let mut packages = Vec::new();
    for (index, fixture) in fixtures.iter().enumerate() {
        if index == 0 {
            packages.push(local.package.clone());
            continue;
        }
        let mut rng = ChaCha20Rng::from_seed([index as u8 + 20; 32]);
        packages.push(
            begin_frost_ceremony(&fixture.config, &fixture.transport_key, &mut rng)
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
