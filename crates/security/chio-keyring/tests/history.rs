use chio_test_support::prelude::*;

use std::collections::BTreeMap;

use chio_core_types::{Ed25519Backend, Keypair, MerkleTree, SigningBackend};
use chio_keyring::{
    derive_key_id, AuthorityId, BootstrapAuthorization, EventId, EventReason,
    KeyActivationCommitBody, KeyLogAuthorizations, KeyLogCheckpointBody, KeyLogEventBody,
    KeyLogOperation, KeyLogPolicy, KeyLogPolicyConfig, LogId, NewKeyProofOfPossession,
    OldKeyAuthorization, RecoveryPolicyId, SignedKeyActivationCommit, SignedKeyLogCheckpoint,
    SignedKeyLogEvent, WitnessId, WitnessRosterId, WitnessSignature, WitnessedActivationSet,
    KEY_ACTIVATION_COMMIT_SCHEMA, KEY_LOG_CHECKPOINT_SCHEMA, KEY_LOG_EVENT_SCHEMA,
};

fn backend(seed: u8) -> Ed25519Backend {
    Ed25519Backend::new(Keypair::from_seed(&[seed; 32]))
}

struct HistoryFixture {
    operator: Ed25519Backend,
    events: Vec<SignedKeyLogEvent>,
    checkpoints: Vec<SignedKeyLogCheckpoint>,
    policy: KeyLogPolicy,
}

impl HistoryFixture {
    fn new() -> Self {
        let bootstrap = backend(1);
        let operator = backend(10);
        let old = backend(2);
        let new = backend(3);
        let witnesses = [backend(20), backend(21), backend(22)];
        let log_id = LogId::new("log.enterprise.test").test_unwrap();
        let authority_id = AuthorityId::new("authority.enterprise.test").test_unwrap();
        let roster_id = WitnessRosterId::new("roster.enterprise.v1").test_unwrap();
        let policy = KeyLogPolicy::new(KeyLogPolicyConfig {
            log_id: log_id.clone(),
            authority_id: authority_id.clone(),
            bootstrap_key: bootstrap.public_key(),
            operator_key: operator.public_key(),
            witness_roster_id: roster_id.clone(),
            witness_keys: BTreeMap::from([
                (
                    WitnessId::new("witness.a").test_unwrap(),
                    witnesses[0].public_key(),
                ),
                (
                    WitnessId::new("witness.b").test_unwrap(),
                    witnesses[1].public_key(),
                ),
                (
                    WitnessId::new("witness.c").test_unwrap(),
                    witnesses[2].public_key(),
                ),
            ]),
            recovery_policy_id: RecoveryPolicyId::new("recovery.enterprise.v1").test_unwrap(),
            recovery_keys: BTreeMap::new(),
            recovery_threshold: 0,
            max_checkpoint_future_skew: 100,
        })
        .test_unwrap();
        let genesis_body = KeyLogEventBody {
            schema: KEY_LOG_EVENT_SCHEMA.to_string(),
            log_id: log_id.clone(),
            sequence: 0,
            event_id: EventId::new("event.genesis").test_unwrap(),
            previous_event_hash: None,
            authority_id: authority_id.clone(),
            key_id: derive_key_id(old.algorithm(), &old.public_key()).test_unwrap(),
            algorithm: old.algorithm(),
            public_key: old.public_key(),
            operation: KeyLogOperation::Genesis,
            effective_at: 1_000,
            verify_until: None,
            reason: Some(EventReason::new("initial key").test_unwrap()),
            issued_at: 1_000,
        };
        let genesis = SignedKeyLogEvent {
            authorizations: KeyLogAuthorizations::bootstrap(
                BootstrapAuthorization::sign(&genesis_body, &bootstrap).test_unwrap(),
            ),
            body: genesis_body,
        };
        let rotation_body = KeyLogEventBody {
            schema: KEY_LOG_EVENT_SCHEMA.to_string(),
            log_id: log_id.clone(),
            sequence: 1,
            event_id: EventId::new("event.rotation.1").test_unwrap(),
            previous_event_hash: Some(genesis.envelope_hash().test_unwrap()),
            authority_id,
            key_id: derive_key_id(new.algorithm(), &new.public_key()).test_unwrap(),
            algorithm: new.algorithm(),
            public_key: new.public_key(),
            operation: KeyLogOperation::Rotate {
                previous_key_id: genesis.body.key_id,
                witness_roster_id: roster_id,
                witness_roster_binding: policy.witness_roster_binding().test_unwrap(),
            },
            effective_at: 8_000,
            verify_until: Some(9_000),
            reason: Some(EventReason::new("rotation").test_unwrap()),
            issued_at: 2_000,
        };
        let rotation = SignedKeyLogEvent {
            authorizations: KeyLogAuthorizations::rotation(
                OldKeyAuthorization::sign(&rotation_body, &old).test_unwrap(),
                NewKeyProofOfPossession::sign(&rotation_body, &new).test_unwrap(),
            ),
            body: rotation_body,
        };
        let events = vec![genesis, rotation];
        let leaves = events
            .iter()
            .map(|event| event.canonical_envelope_bytes().test_unwrap())
            .collect::<Vec<_>>();
        let first = SignedKeyLogCheckpoint::sign(
            KeyLogCheckpointBody {
                schema: KEY_LOG_CHECKPOINT_SCHEMA.to_string(),
                log_id: log_id.clone(),
                checkpoint_sequence: 0,
                tree_size: 1,
                root_hash: MerkleTree::from_leaves(&leaves[..1]).test_unwrap().root(),
                previous_checkpoint_hash: None,
                issued_at: 1_100,
            },
            &operator,
        )
        .test_unwrap();
        let mut second = SignedKeyLogCheckpoint::sign(
            KeyLogCheckpointBody {
                schema: KEY_LOG_CHECKPOINT_SCHEMA.to_string(),
                log_id,
                checkpoint_sequence: 1,
                tree_size: 2,
                root_hash: MerkleTree::from_leaves(&leaves).test_unwrap().root(),
                previous_checkpoint_hash: Some(first.checkpoint_hash().test_unwrap()),
                issued_at: 3_000,
            },
            &operator,
        )
        .test_unwrap();
        second.witness_signatures = vec![
            WitnessSignature::sign(
                &second,
                WitnessId::new("witness.a").test_unwrap(),
                &witnesses[0],
            )
            .test_unwrap(),
            WitnessSignature::sign(
                &second,
                WitnessId::new("witness.b").test_unwrap(),
                &witnesses[1],
            )
            .test_unwrap(),
        ];
        Self {
            operator,
            events,
            checkpoints: vec![first, second],
            policy,
        }
    }

    fn commit(&self) -> SignedKeyActivationCommit {
        SignedKeyActivationCommit::sign(
            KeyActivationCommitBody {
                schema: KEY_ACTIVATION_COMMIT_SCHEMA.to_string(),
                log_id: self.policy.log_id().clone(),
                event_id: self.events[1].body.event_id.clone(),
                checkpoint_hash: self.checkpoints[1].checkpoint_hash().test_unwrap(),
                checkpoint_body_hash: self.checkpoints[1].checkpoint_body_hash().test_unwrap(),
                checkpoint_sequence: self.checkpoints[1].body.checkpoint_sequence,
                tree_size: self.checkpoints[1].body.tree_size,
                root_hash: self.checkpoints[1].body.root_hash,
                event_leaf_hash: self.events[1].merkle_leaf_hash().test_unwrap(),
                witness_set_hash: self.checkpoints[1].witness_set_hash().test_unwrap(),
                witness_signatures: self.checkpoints[1].witness_signatures.clone(),
                committed_at: 3_100,
                signing_epoch: 1,
            },
            &self.operator,
        )
        .test_unwrap()
    }
}

#[test]
fn verified_history_accepts_complete_checkpoint_prefix_and_activation_quorum() {
    let fixture = HistoryFixture::new();
    let history = WitnessedActivationSet::verify_complete(
        &fixture.events,
        &fixture.checkpoints,
        &[fixture.commit()],
        &fixture.policy,
    )
    .test_unwrap();

    assert_eq!(history.tree_size(), 2);
    assert_eq!(history.activation_count(), 1);
}

#[test]
fn history_rejects_omission_fork_chain_break_and_insufficient_witnesses() {
    let fixture = HistoryFixture::new();
    assert!(WitnessedActivationSet::verify_complete(
        &fixture.events,
        &fixture.checkpoints[..1],
        &[],
        &fixture.policy,
    )
    .is_err());

    assert!(WitnessedActivationSet::verify_complete(
        &fixture.events,
        &fixture.checkpoints,
        &[fixture.commit()],
        &fixture.policy,
    )
    .is_ok());

    let mut broken = fixture.checkpoints.clone();
    broken[1].body.previous_checkpoint_hash = None;
    assert!(WitnessedActivationSet::verify_complete(
        &fixture.events,
        &broken,
        &[fixture.commit()],
        &fixture.policy,
    )
    .is_err());

    let mut forked = fixture.checkpoints.clone();
    forked[1].body.root_hash = chio_core_types::sha256(b"fork");
    assert!(WitnessedActivationSet::verify_complete(
        &fixture.events,
        &forked,
        &[fixture.commit()],
        &fixture.policy,
    )
    .is_err());

    let mut insufficient = fixture.checkpoints.clone();
    insufficient[1].witness_signatures.pop();
    let commit = SignedKeyActivationCommit::sign(
        KeyActivationCommitBody {
            checkpoint_hash: insufficient[1].checkpoint_hash().test_unwrap(),
            witness_set_hash: insufficient[1].witness_set_hash().test_unwrap(),
            witness_signatures: insufficient[1].witness_signatures.clone(),
            ..fixture.commit().body
        },
        &fixture.operator,
    )
    .test_unwrap();
    assert!(WitnessedActivationSet::verify_complete(
        &fixture.events,
        &insufficient,
        &[commit],
        &fixture.policy,
    )
    .is_err());
}

#[test]
fn activation_commit_signature_epoch_and_time_are_verified() {
    let fixture = HistoryFixture::new();
    let mut wrong_signer = fixture.commit();
    wrong_signer = SignedKeyActivationCommit::sign(wrong_signer.body, &backend(99)).test_unwrap();
    assert!(WitnessedActivationSet::verify_complete(
        &fixture.events,
        &fixture.checkpoints,
        &[wrong_signer],
        &fixture.policy,
    )
    .is_err());

    let bad_time = SignedKeyActivationCommit::sign(
        KeyActivationCommitBody {
            committed_at: 2_999,
            ..fixture.commit().body
        },
        &fixture.operator,
    )
    .test_unwrap();
    assert!(WitnessedActivationSet::verify_complete(
        &fixture.events,
        &fixture.checkpoints,
        &[bad_time],
        &fixture.policy,
    )
    .is_err());

    let bad_epoch = SignedKeyActivationCommit::sign(
        KeyActivationCommitBody {
            signing_epoch: 2,
            ..fixture.commit().body
        },
        &fixture.operator,
    )
    .test_unwrap();
    assert!(WitnessedActivationSet::verify_complete(
        &fixture.events,
        &fixture.checkpoints,
        &[bad_epoch],
        &fixture.policy,
    )
    .is_err());
}
