use chio_test_support::prelude::*;

use std::collections::BTreeMap;
use std::sync::Arc;

use chio_core_types::{sha256, Ed25519Backend, Keypair, SigningBackend};
use chio_keyring::{
    AnchorId, ArtifactTimeAnchorBody, ArtifactTimeAnchorKind, ArtifactTimeVerifier, AuthorityId,
    KeyLogPolicy, KeyLogPolicyConfig, KeyringError, LogId, RecoveryPolicyId,
    SignedArtifactTimeAnchor, TrustedClock, WitnessId, WitnessRosterId,
    ARTIFACT_TIME_ANCHOR_SCHEMA,
};

fn backend(seed: u8) -> Ed25519Backend {
    Ed25519Backend::new(Keypair::from_seed(&[seed; 32]))
}

struct FixedClock(u64);

impl TrustedClock for FixedClock {
    fn now(&self) -> chio_keyring::Result<u64> {
        Ok(self.0)
    }
}

fn statement(signer: &Ed25519Backend) -> SignedArtifactTimeAnchor {
    SignedArtifactTimeAnchor::sign(
        ArtifactTimeAnchorBody {
            schema: ARTIFACT_TIME_ANCHOR_SCHEMA.to_string(),
            anchor_id: AnchorId::new("timestamp.service.v1").test_unwrap(),
            artifact_hash: sha256(b"artifact"),
            anchored_at: 2_500,
            anchor: ArtifactTimeAnchorKind::External {
                commitment: sha256(b"external-commitment"),
            },
        },
        signer,
    )
    .test_unwrap()
}

fn verifier(trusted: &Ed25519Backend) -> ArtifactTimeVerifier {
    KeyLogPolicy::new(KeyLogPolicyConfig {
        log_id: LogId::new("log.time.test").test_unwrap(),
        authority_id: AuthorityId::new("authority.time.test").test_unwrap(),
        bootstrap_key: backend(1).public_key(),
        operator_key: backend(10).public_key(),
        witness_roster_id: WitnessRosterId::new("roster.time.v1").test_unwrap(),
        witness_keys: BTreeMap::from([(
            WitnessId::new("witness.time").test_unwrap(),
            backend(20).public_key(),
        )]),
        recovery_policy_id: RecoveryPolicyId::new("recovery.time.v1").test_unwrap(),
        recovery_keys: BTreeMap::new(),
        recovery_threshold: 0,
        max_checkpoint_future_skew: 100,
    })
    .test_unwrap()
    .with_artifact_time_roots(BTreeMap::from([(
        AnchorId::new("timestamp.service.v1").test_unwrap(),
        trusted.public_key(),
    )]))
    .test_unwrap()
    .artifact_time_verifier(Arc::new(FixedClock(2_600)), 50)
    .test_unwrap()
}

#[test]
fn configured_trusted_anchor_authenticates_hash_anchor_and_time() {
    let trusted = backend(70);
    let verifier = verifier(&trusted);
    let signed = statement(&trusted);
    let evidence = verifier.verify(&signed).test_unwrap();

    assert_eq!(evidence.artifact_hash(), sha256(b"artifact"));
    assert_eq!(evidence.anchored_at(), 2_500);
    assert_eq!(evidence.anchor(), &signed.body.anchor);
}

#[test]
fn untrusted_tampered_and_future_anchor_statements_fail_closed() {
    let trusted = backend(70);
    let verifier = verifier(&trusted);

    assert!(verifier.verify(&statement(&backend(71))).is_err());

    let mut tampered = statement(&trusted);
    tampered.body.artifact_hash = sha256(b"other-artifact");
    assert!(verifier.verify(&tampered).is_err());

    let future = SignedArtifactTimeAnchor::sign(
        ArtifactTimeAnchorBody {
            anchored_at: 2_651,
            ..statement(&trusted).body
        },
        &trusted,
    )
    .test_unwrap();
    assert!(matches!(
        verifier.verify(&future),
        Err(KeyringError::InvalidArtifactTimeEvidence)
    ));
}

#[test]
fn artifact_time_root_cannot_overlap_any_independent_role() {
    let shared = backend(20);
    let policy = KeyLogPolicy::new(KeyLogPolicyConfig {
        log_id: LogId::new("log.time.overlap").test_unwrap(),
        authority_id: AuthorityId::new("authority.time.overlap").test_unwrap(),
        bootstrap_key: backend(1).public_key(),
        operator_key: backend(10).public_key(),
        witness_roster_id: WitnessRosterId::new("roster.time.overlap").test_unwrap(),
        witness_keys: BTreeMap::from([(
            WitnessId::new("witness.shared").test_unwrap(),
            shared.public_key(),
        )]),
        recovery_policy_id: RecoveryPolicyId::new("recovery.time.overlap").test_unwrap(),
        recovery_keys: BTreeMap::new(),
        recovery_threshold: 0,
        max_checkpoint_future_skew: 100,
    })
    .test_unwrap();
    assert!(policy
        .with_artifact_time_roots(BTreeMap::from([(
            AnchorId::new("timestamp.shared").test_unwrap(),
            shared.public_key(),
        )]))
        .is_err());
}
