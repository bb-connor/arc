use super::*;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

type TestResult = Result<(), Box<dyn std::error::Error>>;
struct Network {
    configs: Vec<FrostCeremonyConfig>,
    signing: Vec<Keypair>,
    sealing: Vec<FrostSealingKey>,
    round1: Vec<FrostRound1Package>,
    round2: Vec<SealedFrostRound2Package>,
    secrets: Vec<FrostCeremonySecret>,
}

fn network() -> Result<Network, FrostCeremonyError> {
    let signing = (1..=5)
        .map(|i| Keypair::from_seed(&[i; 32]))
        .collect::<Vec<_>>();
    let sealing = (11..=15)
        .map(|i| FrostSealingKey::from_custody_bytes(Zeroizing::new([i; 32])))
        .collect::<Vec<_>>();
    let participants = signing
        .iter()
        .zip(&sealing)
        .enumerate()
        .map(|(i, (s, e))| {
            Ok(FrostCeremonyParticipant {
                participant_id: format!("peer-{i}"),
                transport_key_id: format!("sign-{i}"),
                transport_public_key: s.public_key(),
                sealing_key_id: format!("seal-{i}"),
                sealing_public_key: e.public_key()?,
            })
        })
        .collect::<Result<Vec<_>, FrostCeremonyError>>()?;
    let configs = (0..5)
        .map(|i| FrostCeremonyConfig {
            scope_id: "sealed-vector".into(),
            key_epoch: 1,
            threshold: 3,
            predecessor_roster_digest: None,
            participants: participants.clone(),
            local_participant_id: format!("peer-{i}"),
        })
        .collect::<Vec<_>>();
    let mut round1 = Vec::new();
    let mut secrets = Vec::new();
    for i in 0..5 {
        let mut rng = ChaCha20Rng::from_seed([21 + i as u8; 32]);
        let transition = begin_frost_ceremony(&configs[i], &signing[i], &sealing[i], &mut rng)?;
        round1.push(transition.package);
        secrets.push(transition.secret);
    }
    let mut round2 = Vec::new();
    let mut next_secrets = Vec::new();
    for (i, secret) in secrets.into_iter().enumerate() {
        let transition = advance_frost_ceremony(&configs[i], &signing[i], secret, &round1)?;
        for package in transition.packages {
            let recipient = configs
                .iter()
                .position(|c| c.local_participant_id == package.recipient_participant_id())
                .ok_or(FrostSealingError::Recipient)?;
            let opened = package.open(&configs[recipient], &sealing[recipient])?;
            let mut rng = ChaCha20Rng::from_seed([41 + (i * 5 + recipient) as u8; 32]);
            round2.push(SealedFrostRound2Package::seal(
                &ValidatedCeremony::new(&configs[i], &signing[i])?,
                package.recipient_participant_id(),
                opened.bytes.to_vec(),
                &signing[i],
                &mut rng,
            )?);
        }
        next_secrets.push(transition.secret);
    }
    Ok(Network {
        configs,
        signing,
        sealing,
        round1,
        round2,
        secrets: next_secrets,
    })
}

fn expect_error(
    result: Result<FrostRound2Package, FrostCeremonyError>,
    expected: FrostSealingError,
) {
    assert!(
        matches!(&result, Err(FrostCeremonyError::Sealing(actual)) if *actual == expected),
        "expected {expected:?}: {result:?}"
    );
}

#[test]
fn every_three_of_five_pair_matches_vectors_and_produces_a_working_threshold_key() -> TestResult {
    let n = network()?;
    let vector = canonical_json_bytes(&n.round2)?;
    // These public ciphertext bytes also pin roster order, metadata canonicalization,
    // salt decoding, HKDF output split, AEAD and the transport signature preimage.
    let expected = include_bytes!("../../../tests/fixtures/frost-round2-sealed-v1.json");
    assert_eq!(vector.as_slice(), expected.as_slice());
    let observed = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut completions = Vec::new();
    for (i, secret) in n.secrets.into_iter().enumerate() {
        let mut inbox = n
            .round2
            .iter()
            .filter(|p| p.recipient_participant_id() == n.configs[i].local_participant_id)
            .map(|p| p.open(&n.configs[i], &n.sealing[i]))
            .collect::<Result<Vec<_>, _>>()?;
        for package in &mut inbox {
            let observed = observed.clone();
            package.drop_observer = Some(Box::new(move |bytes| {
                assert!(!bytes.is_empty());
                assert!(
                    bytes.iter().all(|byte| *byte == 0),
                    "opened plaintext survived completion"
                );
                observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }));
        }
        let completion =
            complete_frost_ceremony(&n.configs[i], secret, &n.round1, &n.round2, inbox)?;
        completions.push(completion);
    }
    assert_eq!(observed.load(std::sync::atomic::Ordering::SeqCst), 20);
    for pair in completions.windows(2) {
        assert_eq!(pair[0].group_public_key, pair[1].group_public_key);
        assert_eq!(pair[0].transcript_digest, pair[1].transcript_digest);
    }
    let public = PublicKeyPackage::deserialize(&completions[0].public_key_package)?;
    let keys = completions
        .iter()
        .take(3)
        .map(|c| KeyPackage::deserialize(c.key_package.custody_bytes()))
        .collect::<Result<Vec<_>, _>>()?;
    let mut rng = ChaCha20Rng::from_seed([91; 32]);
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for key in &keys {
        let (nonce, commitment) = frost_ed25519::round1::commit(key.signing_share(), &mut rng);
        nonces.insert(*key.identifier(), nonce);
        commitments.insert(*key.identifier(), commitment);
    }
    let message = b"sealed ceremony threshold acceptance";
    let signing = frost_ed25519::SigningPackage::new(commitments, message);
    let mut shares = BTreeMap::new();
    for key in &keys {
        let nonce = nonces.get(key.identifier()).ok_or("missing nonce")?;
        shares.insert(
            *key.identifier(),
            frost_ed25519::round2::sign(&signing, nonce, key)?,
        );
    }
    let signature = frost_ed25519::aggregate(&signing, &shares, &public)?;
    public.verifying_key().verify(message, &signature)?;
    Ok(())
}

#[test]
fn opening_checks_unmodified_foreign_context_before_decryption() -> TestResult {
    let n = network()?;
    let package = &n.round2[0]; // peer-0 -> peer-1
    for change in 0..3 {
        let mut foreign = n.configs[1].clone();
        match change {
            0 => foreign.scope_id = "other-ceremony".into(),
            1 => {
                foreign.key_epoch = 2;
                foreign.predecessor_roster_digest = Some("ab".repeat(32));
            }
            _ => {
                foreign.participants[4].transport_public_key =
                    Keypair::from_seed(&[99; 32]).public_key()
            }
        }
        expect_error(
            package.open(&foreign, &n.sealing[1]),
            FrostSealingError::Context,
        );
    }
    expect_error(
        package.open(&n.configs[2], &n.sealing[2]),
        FrostSealingError::Recipient,
    );
    expect_error(
        package.open(&n.configs[1], &n.sealing[2]),
        FrostSealingError::SealingKey,
    );
    Ok(())
}

#[test]
fn every_metadata_field_and_ciphertext_is_authenticated() -> TestResult {
    let n = network()?;
    let original = &n.round2[0];
    let fields = serde_json::to_value(&original.metadata)?
        .as_object()
        .ok_or("metadata object")?
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    for field in fields {
        let mut json = serde_json::to_value(original)?;
        let expected = match field.as_str() {
            "schema" => FrostSealingError::Schema,
            "suite" => FrostSealingError::Suite,
            "ceremonyId" | "participantSetDigest" | "keyEpoch" | "round" => {
                FrostSealingError::Context
            }
            "recipientParticipantId" => FrostSealingError::Recipient,
            "recipientSealingKeyId" => FrostSealingError::SealingKey,
            "senderParticipantId" => FrostSealingError::Sender,
            "transportKeyId" => FrostSealingError::TransportKey,
            "senderEphemeralPublicKey" => FrostSealingError::Signature,
            _ => panic!("new authenticated field needs a rejection assertion: {field}"),
        };
        match field.as_str() {
            "ceremonyId" | "participantSetDigest" => {
                json[&field] = serde_json::json!("ab".repeat(32))
            }
            "keyEpoch" | "round" => json[&field] = serde_json::json!(99),
            "senderEphemeralPublicKey" => {
                json[&field] = serde_json::to_value(n.sealing[4].public_key()?)?
            }
            _ => json[&field] = serde_json::json!("unrecognized"),
        }
        let changed: SealedFrostRound2Package = serde_json::from_value(json)?;
        expect_error(changed.open(&n.configs[1], &n.sealing[1]), expected);
    }
    for extend in [false, true] {
        let mut changed = original.clone();
        if extend {
            changed.ciphertext.push(0);
        } else {
            changed.ciphertext.pop();
        }
        expect_error(
            changed.open(&n.configs[1], &n.sealing[1]),
            FrostSealingError::Signature,
        );
        changed.transport_signature = n.signing[0].sign(&changed.signing_bytes()?).to_hex();
        expect_error(
            changed.open(&n.configs[1], &n.sealing[1]),
            FrostSealingError::Authentication,
        );
    }
    let mut relabeled = original.clone();
    relabeled.metadata.recipient_participant_id = "peer-2".into();
    relabeled.metadata.recipient_sealing_key_id = "seal-2".into();
    relabeled.transport_signature = n.signing[0].sign(&relabeled.signing_bytes()?).to_hex();
    expect_error(
        relabeled.open(&n.configs[2], &n.sealing[2]),
        FrostSealingError::Authentication,
    );
    Ok(())
}

#[test]
fn parser_and_roster_reject_ambiguous_oversized_and_missing_keys() -> TestResult {
    let n = network()?;
    let wire = canonical_json_bytes(&n.round2[0])?;
    let mut uppercase = n.round2[0].clone();
    uppercase.transport_signature.make_ascii_uppercase();
    expect_error(
        uppercase.open(&n.configs[1], &n.sealing[1]),
        FrostSealingError::Encoding,
    );
    let mut duplicate = b"{\"round\":2,".to_vec();
    duplicate.extend_from_slice(&wire[1..]);
    assert!(matches!(
        SealedFrostRound2Package::from_wire(&duplicate),
        Err(FrostCeremonyError::Sealing(FrostSealingError::Encoding))
    ));
    assert!(matches!(
        SealedFrostRound2Package::from_wire(&vec![b' '; MAX_SEALED_WIRE_BYTES + 1]),
        Err(FrostCeremonyError::Sealing(FrostSealingError::Encoding))
    ));
    let mut roster = n.configs[0].clone();
    roster.participants[1].sealing_public_key =
        serde_json::from_value(serde_json::to_value([0_u8; 32])?)?;
    assert!(matches!(
        roster.validate(),
        Err(FrostCeremonyError::Sealing(FrostSealingError::SealingKey))
    ));
    let mut missing = serde_json::to_value(&n.configs[0])?;
    missing["participants"][1]
        .as_object_mut()
        .ok_or("participant")?
        .remove("sealingKeyId");
    assert!(serde_json::from_value::<FrostCeremonyConfig>(missing).is_err());
    Ok(())
}

#[test]
#[ignore = "explicit vector regeneration; independently verify before committing"]
fn regenerate_sealed_vectors() -> TestResult {
    let n = network()?;
    std::fs::write(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/frost-round2-sealed-v1.json"),
        canonical_json_bytes(&n.round2)?,
    )?;
    let mut inputs = Vec::new();
    for envelope in &n.round2 {
        let sender = n
            .configs
            .iter()
            .position(|c| c.local_participant_id == envelope.sender_participant_id())
            .ok_or("sender")?;
        let recipient = n
            .configs
            .iter()
            .position(|c| c.local_participant_id == envelope.recipient_participant_id())
            .ok_or("recipient")?;
        let mut rng = ChaCha20Rng::from_seed([41 + (sender * 5 + recipient) as u8; 32]);
        let ephemeral = FrostSealingKey::generate(&mut rng)?;
        assert_eq!(
            ephemeral.public_key()?,
            envelope.metadata.sender_ephemeral_public_key
        );
        let opened = envelope.open(&n.configs[recipient], &n.sealing[recipient])?;
        inputs.push(serde_json::json!({"sender":sender, "recipient":recipient,
            "ephemeralPrivateKey":hex::encode(ephemeral.custody_bytes()), "share":hex::encode(&*opened.bytes)}));
    }
    std::fs::write(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/frost-round2-inputs-v1.json"),
        canonical_json_bytes(&serde_json::json!({"config":n.configs[0], "cases":inputs}))?,
    )?;
    Ok(())
}

#[test]
fn authenticated_invalid_agreement_and_plaintext_have_distinct_rejections() -> TestResult {
    let n = network()?;
    let mut low_order = n.round2[0].clone();
    low_order.metadata.sender_ephemeral_public_key =
        serde_json::from_value(serde_json::to_value([0_u8; 32])?)?;
    low_order.transport_signature = n.signing[0].sign(&low_order.signing_bytes()?).to_hex();
    expect_error(
        low_order.open(&n.configs[1], &n.sealing[1]),
        FrostSealingError::Agreement,
    );
    let mut rng = ChaCha20Rng::from_seed([88; 32]);
    let invalid_plaintext = SealedFrostRound2Package::seal(
        &ValidatedCeremony::new(&n.configs[0], &n.signing[0])?,
        "peer-1",
        vec![0; 35],
        &n.signing[0],
        &mut rng,
    )?;
    expect_error(
        invalid_plaintext.open(&n.configs[1], &n.sealing[1]),
        FrostSealingError::Plaintext,
    );
    Ok(())
}
