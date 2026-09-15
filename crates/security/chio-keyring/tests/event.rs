use chio_test_support::prelude::*;

use chio_core_types::{Ed25519Backend, Hash, Keypair, SigningAlgorithm, SigningBackend};
use chio_keyring::{
    derive_key_id, AuthorityId, BootstrapAuthorization, EventId, EventReason, KeyLogAuthorizations,
    KeyLogEventBody, KeyLogOperation, LogId, NewKeyProofOfPossession, OldKeyAuthorization,
    RecoveryAuthorization, RecoveryAuthorizerId, SignedKeyLogEvent, WitnessRosterId,
    KEY_LOG_EVENT_SCHEMA, MAX_CANONICAL_RECORD_BYTES, MAX_RECOVERY_AUTHORIZATIONS,
};

fn backend(seed: u8) -> Ed25519Backend {
    Ed25519Backend::new(Keypair::from_seed(&[seed; 32]))
}

#[test]
fn recovery_authorizations_are_sorted_and_bounded_before_vector_growth() {
    let signer = backend(50);
    let body = genesis(&backend(1), &backend(2)).body;
    let authorization = |id: &str| {
        RecoveryAuthorization::sign(&body, RecoveryAuthorizerId::new(id).test_unwrap(), &signer)
            .test_unwrap()
    };
    let sorted = KeyLogAuthorizations::recovery(vec![
        authorization("recovery.b"),
        authorization("recovery.a"),
    ]);
    assert_eq!(
        sorted
            .recovery
            .iter()
            .map(|item| item.authorizer_id.as_str())
            .collect::<Vec<_>>(),
        vec!["recovery.a", "recovery.b"]
    );

    let oversized = KeyLogAuthorizations {
        recovery: (0..=MAX_RECOVERY_AUTHORIZATIONS)
            .map(|index| authorization(&format!("recovery.{index:03}")))
            .collect(),
        ..KeyLogAuthorizations::default()
    };
    let encoded = serde_json::to_vec(&oversized).test_unwrap();
    assert!(serde_json::from_slice::<KeyLogAuthorizations>(&encoded).is_err());

    let bytes = vec![b' '; MAX_CANONICAL_RECORD_BYTES + 1];
    assert!(SignedKeyLogEvent::from_canonical_envelope_bytes(&bytes).is_err());
}

fn genesis(bootstrap: &Ed25519Backend, authority: &Ed25519Backend) -> SignedKeyLogEvent {
    let body = KeyLogEventBody {
        schema: KEY_LOG_EVENT_SCHEMA.to_string(),
        log_id: LogId::new("log.enterprise.test").test_unwrap(),
        sequence: 0,
        event_id: EventId::new("event.genesis").test_unwrap(),
        previous_event_hash: None,
        authority_id: AuthorityId::new("authority.enterprise.test").test_unwrap(),
        key_id: derive_key_id(authority.algorithm(), &authority.public_key()).test_unwrap(),
        algorithm: authority.algorithm(),
        public_key: authority.public_key(),
        operation: KeyLogOperation::Genesis,
        effective_at: 1_000,
        verify_until: None,
        reason: Some(EventReason::new("initial authority key").test_unwrap()),
        issued_at: 1_000,
    };
    let authorization = BootstrapAuthorization::sign(&body, bootstrap).test_unwrap();
    SignedKeyLogEvent {
        body,
        authorizations: KeyLogAuthorizations::bootstrap(authorization),
    }
}

fn rotation(
    previous: &SignedKeyLogEvent,
    old: &Ed25519Backend,
    new: &Ed25519Backend,
) -> SignedKeyLogEvent {
    let body = KeyLogEventBody {
        schema: KEY_LOG_EVENT_SCHEMA.to_string(),
        log_id: previous.body.log_id.clone(),
        sequence: 1,
        event_id: EventId::new("event.rotation.1").test_unwrap(),
        previous_event_hash: Some(previous.envelope_hash().test_unwrap()),
        authority_id: previous.body.authority_id.clone(),
        key_id: derive_key_id(new.algorithm(), &new.public_key()).test_unwrap(),
        algorithm: new.algorithm(),
        public_key: new.public_key(),
        operation: KeyLogOperation::Rotate {
            previous_key_id: previous.body.key_id,
            witness_roster_id: WitnessRosterId::new("roster.enterprise.v1").test_unwrap(),
            witness_roster_binding: Hash::zero(),
        },
        effective_at: 2_000,
        verify_until: Some(9_000),
        reason: Some(EventReason::new("scheduled rotation").test_unwrap()),
        issued_at: 2_000,
    };
    SignedKeyLogEvent {
        authorizations: KeyLogAuthorizations::rotation(
            OldKeyAuthorization::sign(&body, old).test_unwrap(),
            NewKeyProofOfPossession::sign(&body, new).test_unwrap(),
        ),
        body,
    }
}

#[test]
fn canonical_body_and_complete_envelope_are_stable_and_non_self_referential() {
    let bootstrap = backend(1);
    let authority = backend(2);
    let event = genesis(&bootstrap, &authority);

    let body_bytes = event.body.signing_bytes().test_unwrap();
    let envelope_bytes = event.canonical_envelope_bytes().test_unwrap();
    let restored: SignedKeyLogEvent = serde_json::from_slice(&envelope_bytes).test_unwrap();

    assert_eq!(restored, event);
    assert_eq!(restored.body.signing_bytes().test_unwrap(), body_bytes);
    assert_eq!(
        restored.canonical_envelope_bytes().test_unwrap(),
        envelope_bytes
    );
    assert!(!body_bytes
        .windows(
            event
                .authorizations
                .bootstrap
                .as_ref()
                .test_unwrap()
                .signature
                .to_hex()
                .len()
        )
        .any(|window| window
            == event
                .authorizations
                .bootstrap
                .as_ref()
                .test_unwrap()
                .signature
                .to_hex()
                .as_bytes()));
}

#[test]
fn complete_envelope_hash_and_merkle_leaf_cover_every_signature_byte() {
    let bootstrap = backend(1);
    let authority = backend(2);
    let event = genesis(&bootstrap, &authority);
    let original_envelope_hash = event.envelope_hash().test_unwrap();
    let original_leaf_hash = event.merkle_leaf_hash().test_unwrap();

    let mut tampered = event.clone();
    tampered.authorizations.bootstrap =
        Some(BootstrapAuthorization::sign(&tampered.body, &backend(9)).test_unwrap());

    assert_ne!(
        tampered.envelope_hash().test_unwrap(),
        original_envelope_hash
    );
    assert_ne!(
        tampered.merkle_leaf_hash().test_unwrap(),
        original_leaf_hash
    );
    assert_eq!(
        tampered.body.signing_bytes().test_unwrap(),
        event.body.signing_bytes().test_unwrap()
    );
}

#[test]
fn key_id_binds_algorithm_and_complete_self_describing_public_key() {
    let authority = backend(2);
    let key = authority.public_key();
    let ed25519 = derive_key_id(SigningAlgorithm::Ed25519, &key).test_unwrap();

    assert!(derive_key_id(SigningAlgorithm::P256, &key).is_err());
    assert_eq!(ed25519, derive_key_id(key.algorithm(), &key).test_unwrap());
    assert_ne!(
        ed25519,
        derive_key_id(backend(3).algorithm(), &backend(3).public_key()).test_unwrap()
    );
}

#[test]
fn genesis_and_rotation_require_exact_authorization_sets() {
    let bootstrap = backend(1);
    let old = backend(2);
    let new = backend(3);
    let genesis = genesis(&bootstrap, &old);
    genesis
        .verify_genesis(&bootstrap.public_key())
        .test_unwrap();

    let rotation = rotation(&genesis, &old, &new);
    rotation.verify_rotation(&old.public_key()).test_unwrap();

    let mut bad_old = rotation.clone();
    bad_old.authorizations.old_key =
        Some(OldKeyAuthorization::sign(&bad_old.body, &backend(8)).test_unwrap());
    assert!(bad_old.verify_rotation(&old.public_key()).is_err());

    let mut bad_new = rotation.clone();
    bad_new.authorizations.new_key =
        Some(NewKeyProofOfPossession::sign(&bad_new.body, &backend(8)).test_unwrap());
    assert!(bad_new.verify_rotation(&old.public_key()).is_err());

    let mut missing = rotation;
    missing.authorizations.new_key = None;
    assert!(missing.verify_rotation(&old.public_key()).is_err());
}

#[test]
fn common_validation_rejects_schema_sequence_predecessor_and_time_errors() {
    let bootstrap = backend(1);
    let authority = backend(2);
    let event = genesis(&bootstrap, &authority);

    event
        .validate_common(0, None, &event.body.log_id, &event.body.authority_id, None)
        .test_unwrap();

    let mut unknown = serde_json::to_value(&event.body).test_unwrap();
    unknown
        .as_object_mut()
        .test_unwrap()
        .insert("unknown".to_string(), serde_json::json!(true));
    assert!(serde_json::from_value::<KeyLogEventBody>(unknown).is_err());

    assert!(event
        .validate_common(1, None, &event.body.log_id, &event.body.authority_id, None)
        .is_err());
    assert!(event
        .validate_common(
            0,
            Some(&Hash::zero()),
            &event.body.log_id,
            &event.body.authority_id,
            None,
        )
        .is_err());

    let mut reversed = event;
    reversed.body.effective_at = 999;
    assert!(reversed
        .validate_common(
            0,
            None,
            &reversed.body.log_id,
            &reversed.body.authority_id,
            None,
        )
        .is_err());
}
