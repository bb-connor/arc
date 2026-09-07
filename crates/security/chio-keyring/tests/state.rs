use chio_test_support::prelude::*;

use std::collections::BTreeMap;
use std::sync::Arc;

use chio_core_types::{sha256, Ed25519Backend, Keypair, MerkleTree, SigningBackend};
use chio_keyring::{
    derive_key_id, AnchorId, ArtifactTimeAnchorBody, ArtifactTimeAnchorKind, ArtifactTimeEvidence,
    AuthorityId, BootstrapAuthorization, EventId, EventReason, KeyActivationCommitBody,
    KeyLogAuthorizations, KeyLogCheckpointBody, KeyLogEventBody, KeyLogOperation, KeyLogPolicy,
    KeyLogPolicyConfig, KeyLogState, KeyStatus, LogId, NewKeyProofOfPossession,
    OldKeyAuthorization, RecoveryAuthorization, RecoveryAuthorizerId, RecoveryPolicyId,
    SignedArtifactTimeAnchor, SignedKeyActivationCommit, SignedKeyLogCheckpoint, SignedKeyLogEvent,
    TrustedClock, WitnessId, WitnessRosterId, WitnessSignature, WitnessedActivationSet,
    ARTIFACT_TIME_ANCHOR_SCHEMA, KEY_ACTIVATION_COMMIT_SCHEMA, KEY_LOG_CHECKPOINT_SCHEMA,
    KEY_LOG_EVENT_SCHEMA, MAX_RECOVERY_AUTHORIZATIONS,
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

struct Fixture {
    bootstrap: Ed25519Backend,
    operator: Ed25519Backend,
    old: Ed25519Backend,
    new: Ed25519Backend,
    witness_a: Ed25519Backend,
    witness_b: Ed25519Backend,
    witness_c: Ed25519Backend,
    recovery_a: Ed25519Backend,
    recovery_b: Ed25519Backend,
}

impl Fixture {
    fn new() -> Self {
        Self {
            bootstrap: backend(1),
            operator: backend(10),
            old: backend(2),
            new: backend(3),
            witness_a: backend(20),
            witness_b: backend(21),
            witness_c: backend(22),
            recovery_a: backend(30),
            recovery_b: backend(31),
        }
    }

    fn policy_without_auditors(&self) -> KeyLogPolicy {
        KeyLogPolicy::new(KeyLogPolicyConfig {
            log_id: LogId::new("log.enterprise.test").test_unwrap(),
            authority_id: AuthorityId::new("authority.enterprise.test").test_unwrap(),
            bootstrap_key: self.bootstrap.public_key(),
            operator_key: self.operator.public_key(),
            witness_roster_id: WitnessRosterId::new("roster.enterprise.v1").test_unwrap(),
            witness_keys: BTreeMap::from([
                (
                    WitnessId::new("witness.a").test_unwrap(),
                    self.witness_a.public_key(),
                ),
                (
                    WitnessId::new("witness.b").test_unwrap(),
                    self.witness_b.public_key(),
                ),
                (
                    WitnessId::new("witness.c").test_unwrap(),
                    self.witness_c.public_key(),
                ),
            ]),
            recovery_policy_id: RecoveryPolicyId::new("recovery.enterprise.v1").test_unwrap(),
            recovery_keys: BTreeMap::from([
                (
                    RecoveryAuthorizerId::new("recovery.a").test_unwrap(),
                    self.recovery_a.public_key(),
                ),
                (
                    RecoveryAuthorizerId::new("recovery.b").test_unwrap(),
                    self.recovery_b.public_key(),
                ),
            ]),
            recovery_threshold: 2,
            max_checkpoint_future_skew: 100,
        })
        .test_unwrap()
        .with_artifact_time_roots(BTreeMap::from([(
            AnchorId::new("timestamp.service.v1").test_unwrap(),
            backend(70).public_key(),
        )]))
        .test_unwrap()
    }

    fn auditor_public_keys(&self) -> BTreeMap<String, chio_core_types::PublicKey> {
        BTreeMap::from([
            ("audit.a".to_string(), backend(80).public_key()),
            ("audit.b".to_string(), backend(81).public_key()),
        ])
    }

    fn policy(&self) -> KeyLogPolicy {
        self.policy_without_auditors()
            .with_auditor_roots(self.auditor_public_keys())
            .test_unwrap()
    }

    fn genesis(&self) -> SignedKeyLogEvent {
        let body = KeyLogEventBody {
            schema: KEY_LOG_EVENT_SCHEMA.to_string(),
            log_id: LogId::new("log.enterprise.test").test_unwrap(),
            sequence: 0,
            event_id: EventId::new("event.genesis").test_unwrap(),
            previous_event_hash: None,
            authority_id: AuthorityId::new("authority.enterprise.test").test_unwrap(),
            key_id: derive_key_id(self.old.algorithm(), &self.old.public_key()).test_unwrap(),
            algorithm: self.old.algorithm(),
            public_key: self.old.public_key(),
            operation: KeyLogOperation::Genesis,
            effective_at: 1_000,
            verify_until: None,
            reason: Some(EventReason::new("initial authority key").test_unwrap()),
            issued_at: 1_000,
        };
        SignedKeyLogEvent {
            authorizations: KeyLogAuthorizations::bootstrap(
                BootstrapAuthorization::sign(&body, &self.bootstrap).test_unwrap(),
            ),
            body,
        }
    }

    fn rotation(&self, genesis: &SignedKeyLogEvent) -> SignedKeyLogEvent {
        let body = KeyLogEventBody {
            schema: KEY_LOG_EVENT_SCHEMA.to_string(),
            log_id: genesis.body.log_id.clone(),
            sequence: 1,
            event_id: EventId::new("event.rotation.1").test_unwrap(),
            previous_event_hash: Some(genesis.envelope_hash().test_unwrap()),
            authority_id: genesis.body.authority_id.clone(),
            key_id: derive_key_id(self.new.algorithm(), &self.new.public_key()).test_unwrap(),
            algorithm: self.new.algorithm(),
            public_key: self.new.public_key(),
            operation: KeyLogOperation::Rotate {
                previous_key_id: genesis.body.key_id,
                witness_roster_id: WitnessRosterId::new("roster.enterprise.v1").test_unwrap(),
                witness_roster_binding: self.policy().witness_roster_binding().test_unwrap(),
            },
            effective_at: 2_000,
            verify_until: Some(9_000),
            reason: Some(EventReason::new("scheduled rotation").test_unwrap()),
            issued_at: 2_000,
        };
        SignedKeyLogEvent {
            authorizations: KeyLogAuthorizations::rotation(
                OldKeyAuthorization::sign(&body, &self.old).test_unwrap(),
                NewKeyProofOfPossession::sign(&body, &self.new).test_unwrap(),
            ),
            body,
        }
    }

    fn checkpoints(
        &self,
        events: &[&SignedKeyLogEvent],
        witnessed_index: Option<usize>,
    ) -> Vec<SignedKeyLogCheckpoint> {
        let leaves = events
            .iter()
            .map(|event| event.canonical_envelope_bytes().test_unwrap())
            .collect::<Vec<_>>();
        let mut checkpoints = Vec::with_capacity(events.len());
        let mut predecessor = None;
        for (index, event) in events.iter().enumerate() {
            let mut checkpoint = SignedKeyLogCheckpoint::sign(
                KeyLogCheckpointBody {
                    schema: KEY_LOG_CHECKPOINT_SCHEMA.to_string(),
                    log_id: event.body.log_id.clone(),
                    checkpoint_sequence: u64::try_from(index).test_unwrap(),
                    tree_size: u64::try_from(index + 1).test_unwrap(),
                    root_hash: MerkleTree::from_leaves(&leaves[..=index])
                        .test_unwrap()
                        .root(),
                    previous_checkpoint_hash: predecessor,
                    issued_at: event.body.issued_at + 1_000,
                },
                &self.operator,
            )
            .test_unwrap();
            if witnessed_index == Some(index) {
                checkpoint.witness_signatures = vec![
                    WitnessSignature::sign(
                        &checkpoint,
                        WitnessId::new("witness.a").test_unwrap(),
                        &self.witness_a,
                    )
                    .test_unwrap(),
                    WitnessSignature::sign(
                        &checkpoint,
                        WitnessId::new("witness.b").test_unwrap(),
                        &self.witness_b,
                    )
                    .test_unwrap(),
                ];
            }
            predecessor = Some(checkpoint.checkpoint_hash().test_unwrap());
            checkpoints.push(checkpoint);
        }
        checkpoints
    }

    fn activation_materials(
        &self,
        events: &[&SignedKeyLogEvent],
        activation_index: usize,
    ) -> (Vec<SignedKeyLogCheckpoint>, SignedKeyActivationCommit) {
        let checkpoints = self.checkpoints(events, Some(activation_index));
        let checkpoint = &checkpoints[activation_index];
        let commit = SignedKeyActivationCommit::sign(
            KeyActivationCommitBody {
                schema: KEY_ACTIVATION_COMMIT_SCHEMA.to_string(),
                log_id: events[activation_index].body.log_id.clone(),
                event_id: events[activation_index].body.event_id.clone(),
                checkpoint_hash: checkpoint.checkpoint_hash().test_unwrap(),
                checkpoint_body_hash: checkpoint.checkpoint_body_hash().test_unwrap(),
                checkpoint_sequence: checkpoint.body.checkpoint_sequence,
                tree_size: checkpoint.body.tree_size,
                root_hash: checkpoint.body.root_hash,
                event_leaf_hash: events[activation_index].merkle_leaf_hash().test_unwrap(),
                witness_set_hash: checkpoint.witness_set_hash().test_unwrap(),
                witness_signatures: checkpoint.witness_signatures.clone(),
                committed_at: checkpoint.body.issued_at + 10,
                signing_epoch: 1,
            },
            &self.operator,
        )
        .test_unwrap();
        (checkpoints, commit)
    }

    fn history(
        &self,
        events: &[&SignedKeyLogEvent],
        activation_index: Option<usize>,
    ) -> WitnessedActivationSet {
        let owned = events
            .iter()
            .map(|event| (*event).clone())
            .collect::<Vec<_>>();
        let (checkpoints, commits) = if let Some(index) = activation_index {
            let (checkpoints, commit) = self.activation_materials(events, index);
            (checkpoints, vec![commit])
        } else {
            (self.checkpoints(events, None), Vec::new())
        };
        WitnessedActivationSet::verify_complete(&owned, &checkpoints, &commits, &self.policy())
            .test_unwrap()
    }
}

#[test]
fn trust_policy_bindings_commit_roster_keys_and_recovery_threshold() {
    let fixture = Fixture::new();
    let policy = fixture.policy();
    let changed_recovery_threshold = KeyLogPolicy::new(KeyLogPolicyConfig {
        log_id: policy.log_id().clone(),
        authority_id: policy.authority_id().clone(),
        bootstrap_key: fixture.bootstrap.public_key(),
        operator_key: fixture.operator.public_key(),
        witness_roster_id: WitnessRosterId::new("roster.enterprise.v1").test_unwrap(),
        witness_keys: BTreeMap::from([
            (
                WitnessId::new("witness.a").test_unwrap(),
                fixture.witness_a.public_key(),
            ),
            (
                WitnessId::new("witness.b").test_unwrap(),
                fixture.witness_b.public_key(),
            ),
            (
                WitnessId::new("witness.c").test_unwrap(),
                fixture.witness_c.public_key(),
            ),
        ]),
        recovery_policy_id: RecoveryPolicyId::new("recovery.enterprise.v1").test_unwrap(),
        recovery_keys: BTreeMap::from([
            (
                RecoveryAuthorizerId::new("recovery.a").test_unwrap(),
                fixture.recovery_a.public_key(),
            ),
            (
                RecoveryAuthorizerId::new("recovery.b").test_unwrap(),
                fixture.recovery_b.public_key(),
            ),
        ]),
        recovery_threshold: 1,
        max_checkpoint_future_skew: 100,
    })
    .test_unwrap()
    .with_artifact_time_roots(BTreeMap::from([(
        AnchorId::new("timestamp.service.v1").test_unwrap(),
        backend(70).public_key(),
    )]))
    .test_unwrap()
    .with_auditor_roots(fixture.auditor_public_keys())
    .test_unwrap();
    assert_eq!(
        policy.witness_roster_binding().test_unwrap(),
        changed_recovery_threshold
            .witness_roster_binding()
            .test_unwrap()
    );
    assert_ne!(
        policy.recovery_policy_binding().test_unwrap(),
        changed_recovery_threshold
            .recovery_policy_binding()
            .test_unwrap()
    );
    assert_ne!(
        policy.configuration_binding().test_unwrap(),
        changed_recovery_threshold
            .configuration_binding()
            .test_unwrap()
    );
}

#[test]
fn auditor_policy_requires_exactly_two_unique_identifiers_and_role_keys() {
    let fixture = Fixture::new();
    let base = fixture.policy_without_auditors();

    assert!(base.clone().with_auditor_roots(BTreeMap::new()).is_err());
    assert!(base
        .clone()
        .with_auditor_roots(BTreeMap::from([(
            "audit.a".to_string(),
            backend(80).public_key(),
        )]))
        .is_err());
    assert!(base
        .clone()
        .with_auditor_roots(BTreeMap::from([
            ("audit.a".to_string(), backend(80).public_key()),
            ("audit.b".to_string(), backend(81).public_key()),
            ("audit.c".to_string(), backend(82).public_key()),
        ]))
        .is_err());
    assert!(base
        .clone()
        .with_auditor_roots(BTreeMap::from([
            ("audit.a".to_string(), backend(80).public_key()),
            ("audit.b".to_string(), backend(80).public_key()),
        ]))
        .is_err());
    assert!(base
        .clone()
        .with_auditor_roots(BTreeMap::from([
            ("audit valid".to_string(), backend(80).public_key()),
            ("audit.b".to_string(), backend(81).public_key()),
        ]))
        .is_err());

    let policy = base
        .with_auditor_roots(fixture.auditor_public_keys())
        .test_unwrap();
    assert_eq!(policy.auditor_public_keys(), &fixture.auditor_public_keys());
}

#[test]
fn auditor_keys_cannot_overlap_any_fixed_or_lifecycle_authority_role() {
    let fixture = Fixture::new();
    for overlapping_key in [
        fixture.bootstrap.public_key(),
        fixture.operator.public_key(),
        fixture.witness_a.public_key(),
        fixture.recovery_a.public_key(),
        backend(70).public_key(),
    ] {
        assert!(fixture
            .policy_without_auditors()
            .with_auditor_roots(BTreeMap::from([
                ("audit.a".to_string(), overlapping_key),
                ("audit.b".to_string(), backend(81).public_key()),
            ]))
            .is_err());
    }

    let policy = fixture.policy();
    let auditor = backend(80);
    let mut active_overlap = fixture.genesis();
    active_overlap.body.key_id =
        derive_key_id(auditor.algorithm(), &auditor.public_key()).test_unwrap();
    active_overlap.body.algorithm = auditor.algorithm();
    active_overlap.body.public_key = auditor.public_key();
    active_overlap.authorizations = KeyLogAuthorizations::bootstrap(
        BootstrapAuthorization::sign(&active_overlap.body, &fixture.bootstrap).test_unwrap(),
    );
    let active_history = fixture.history(&[&active_overlap], None);
    assert!(KeyLogState::replay([&active_overlap], &active_history, &policy).is_err());

    let genesis = fixture.genesis();
    let mut pending_overlap = fixture.rotation(&genesis);
    pending_overlap.body.key_id =
        derive_key_id(auditor.algorithm(), &auditor.public_key()).test_unwrap();
    pending_overlap.body.algorithm = auditor.algorithm();
    pending_overlap.body.public_key = auditor.public_key();
    pending_overlap.authorizations = KeyLogAuthorizations::rotation(
        OldKeyAuthorization::sign(&pending_overlap.body, &fixture.old).test_unwrap(),
        NewKeyProofOfPossession::sign(&pending_overlap.body, &auditor).test_unwrap(),
    );
    let pending_history = fixture.history(&[&genesis, &pending_overlap], None);
    assert!(KeyLogState::replay([&genesis, &pending_overlap], &pending_history, &policy,).is_err());
}

#[test]
fn configuration_binding_commits_the_canonical_auditor_roster() {
    let fixture = Fixture::new();
    let base = fixture.policy_without_auditors();
    let original = base
        .clone()
        .with_auditor_roots(fixture.auditor_public_keys())
        .test_unwrap();
    let changed_identifier = base
        .clone()
        .with_auditor_roots(BTreeMap::from([
            ("audit.a".to_string(), backend(80).public_key()),
            ("audit.c".to_string(), backend(81).public_key()),
        ]))
        .test_unwrap();
    let changed_key = base
        .with_auditor_roots(BTreeMap::from([
            ("audit.a".to_string(), backend(80).public_key()),
            ("audit.b".to_string(), backend(82).public_key()),
        ]))
        .test_unwrap();

    assert_ne!(
        original.auditor_policy_binding().test_unwrap(),
        changed_identifier.auditor_policy_binding().test_unwrap()
    );
    assert_ne!(
        original.auditor_policy_binding().test_unwrap(),
        changed_key.auditor_policy_binding().test_unwrap()
    );
    assert_ne!(
        original.configuration_binding().test_unwrap(),
        changed_identifier.configuration_binding().test_unwrap()
    );
    assert_ne!(
        original.configuration_binding().test_unwrap(),
        changed_key.configuration_binding().test_unwrap()
    );
}

fn verified_time_evidence(
    policy: &KeyLogPolicy,
    artifact_hash: chio_core_types::Hash,
    anchored_at: u64,
) -> ArtifactTimeEvidence {
    let signer = backend(70);
    let anchor_id = AnchorId::new("timestamp.service.v1").test_unwrap();
    let verifier = policy
        .artifact_time_verifier(Arc::new(FixedClock(anchored_at)), 0)
        .test_unwrap();
    verifier
        .verify(
            &SignedArtifactTimeAnchor::sign(
                ArtifactTimeAnchorBody {
                    schema: ARTIFACT_TIME_ANCHOR_SCHEMA.to_string(),
                    anchor_id,
                    artifact_hash,
                    anchored_at,
                    anchor: ArtifactTimeAnchorKind::External {
                        commitment: sha256(b"timestamp-commitment"),
                    },
                },
                &signer,
            )
            .test_unwrap(),
        )
        .test_unwrap()
}

#[test]
fn genesis_and_pending_rotation_preserve_one_active_signer() {
    let fixture = Fixture::new();
    let policy = fixture.policy();
    let genesis = fixture.genesis();
    let rotation = fixture.rotation(&genesis);

    let genesis_history = fixture.history(&[&genesis], None);
    let genesis_state = KeyLogState::replay([&genesis], &genesis_history, &policy).test_unwrap();
    assert_eq!(
        genesis_state.active_signing_key().test_unwrap().key_id,
        genesis.body.key_id
    );

    let pending_history = fixture.history(&[&genesis, &rotation], None);
    let pending =
        KeyLogState::replay([&genesis, &rotation], &pending_history, &policy).test_unwrap();
    assert_eq!(
        pending.active_signing_key().test_unwrap().key_id,
        genesis.body.key_id
    );
    assert_eq!(
        pending.pending_rotation_key().test_unwrap().key_id,
        rotation.body.key_id
    );
    assert_eq!(
        pending.pending_rotation_key().test_unwrap().status,
        KeyStatus::Pending
    );
    assert_eq!(pending.signing_epoch(), 0);
}

#[test]
fn witnessed_rotation_uses_signed_commit_time_and_strict_majority() {
    let fixture = Fixture::new();
    let policy = fixture.policy();
    let genesis = fixture.genesis();
    let mut rotation = fixture.rotation(&genesis);
    rotation.body.effective_at = 8_000;
    rotation.authorizations = KeyLogAuthorizations::rotation(
        OldKeyAuthorization::sign(&rotation.body, &fixture.old).test_unwrap(),
        NewKeyProofOfPossession::sign(&rotation.body, &fixture.new).test_unwrap(),
    );
    let events = vec![genesis.clone(), rotation.clone()];
    let (checkpoints, commit) = fixture.activation_materials(&[&genesis, &rotation], 1);
    let history = WitnessedActivationSet::verify_complete(
        &events,
        &checkpoints,
        std::slice::from_ref(&commit),
        &policy,
    )
    .test_unwrap();
    let state = KeyLogState::replay([&genesis, &rotation], &history, &policy).test_unwrap();
    assert_eq!(
        state.active_signing_key().test_unwrap().key_id,
        rotation.body.key_id
    );
    assert_eq!(state.active_signing_key().test_unwrap().activated_at, 3_010);
    assert_eq!(state.signing_epoch(), 1);

    let mut insufficient_body = commit.body.clone();
    insufficient_body.witness_signatures.pop();
    insufficient_body.witness_set_hash = {
        let mut checkpoint = checkpoints[1].clone();
        checkpoint.witness_signatures = insufficient_body.witness_signatures.clone();
        checkpoint.witness_set_hash().test_unwrap()
    };
    let insufficient =
        SignedKeyActivationCommit::sign(insufficient_body, &fixture.operator).test_unwrap();
    assert!(WitnessedActivationSet::verify_complete(
        &events,
        &checkpoints,
        std::slice::from_ref(&insufficient),
        &policy,
    )
    .is_err());

    let bad_time = SignedKeyActivationCommit::sign(
        KeyActivationCommitBody {
            committed_at: 2_999,
            ..commit.body
        },
        &fixture.operator,
    )
    .test_unwrap();
    assert!(
        WitnessedActivationSet::verify_complete(&events, &checkpoints, &[bad_time], &policy)
            .is_err()
    );
}

#[test]
fn trusted_artifact_time_evidence_blocks_post_deactivation_and_preactivation_use() {
    let fixture = Fixture::new();
    let policy = fixture.policy();
    let genesis = fixture.genesis();
    let rotation = fixture.rotation(&genesis);
    let history = fixture.history(&[&genesis, &rotation], Some(1));
    let state = KeyLogState::replay([&genesis, &rotation], &history, &policy).test_unwrap();
    let artifact_hash = sha256(b"artifact");

    let valid_old = verified_time_evidence(&policy, artifact_hash, 2_500);
    assert!(state
        .verification_key_for_artifact(&genesis.body.key_id, &artifact_hash, &valid_old)
        .is_ok());
    let foreign_policy = KeyLogPolicy::new(KeyLogPolicyConfig {
        log_id: LogId::new("log.foreign.enterprise.test").test_unwrap(),
        authority_id: AuthorityId::new("authority.foreign.enterprise.test").test_unwrap(),
        bootstrap_key: fixture.bootstrap.public_key(),
        operator_key: fixture.operator.public_key(),
        witness_roster_id: WitnessRosterId::new("roster.foreign.enterprise.v1").test_unwrap(),
        witness_keys: BTreeMap::from([
            (
                WitnessId::new("witness.a").test_unwrap(),
                fixture.witness_a.public_key(),
            ),
            (
                WitnessId::new("witness.b").test_unwrap(),
                fixture.witness_b.public_key(),
            ),
            (
                WitnessId::new("witness.c").test_unwrap(),
                fixture.witness_c.public_key(),
            ),
        ]),
        recovery_policy_id: RecoveryPolicyId::new("recovery.foreign.enterprise.v1").test_unwrap(),
        recovery_keys: BTreeMap::from([
            (
                RecoveryAuthorizerId::new("recovery.a").test_unwrap(),
                fixture.recovery_a.public_key(),
            ),
            (
                RecoveryAuthorizerId::new("recovery.b").test_unwrap(),
                fixture.recovery_b.public_key(),
            ),
        ]),
        recovery_threshold: 2,
        max_checkpoint_future_skew: 100,
    })
    .test_unwrap()
    .with_artifact_time_roots(BTreeMap::from([(
        AnchorId::new("timestamp.service.v1").test_unwrap(),
        backend(70).public_key(),
    )]))
    .test_unwrap();
    let foreign_evidence = verified_time_evidence(&foreign_policy, artifact_hash, 2_500);
    assert!(state
        .verification_key_for_artifact(&genesis.body.key_id, &artifact_hash, &foreign_evidence)
        .is_err());
    let after_deactivation = verified_time_evidence(&policy, artifact_hash, 3_011);
    assert!(state
        .verification_key_for_artifact(&genesis.body.key_id, &artifact_hash, &after_deactivation,)
        .is_err());
    assert!(state
        .verification_key_for_artifact(&genesis.body.key_id, &sha256(b"other"), &valid_old)
        .is_err());
    let preactivation = verified_time_evidence(&policy, artifact_hash, 3_009);
    assert!(state
        .verification_key_for_artifact(&rotation.body.key_id, &artifact_hash, &preactivation)
        .is_err());
}

#[test]
fn abort_retire_and_revoke_are_immutable_events() {
    let fixture = Fixture::new();
    let policy = fixture.policy();
    let genesis = fixture.genesis();
    let rotation = fixture.rotation(&genesis);
    let abort_body = KeyLogEventBody {
        schema: KEY_LOG_EVENT_SCHEMA.to_string(),
        log_id: genesis.body.log_id.clone(),
        sequence: 2,
        event_id: EventId::new("event.abort.1").test_unwrap(),
        previous_event_hash: Some(rotation.envelope_hash().test_unwrap()),
        authority_id: genesis.body.authority_id.clone(),
        key_id: rotation.body.key_id,
        algorithm: rotation.body.algorithm,
        public_key: rotation.body.public_key.clone(),
        operation: KeyLogOperation::AbortRotation {
            previous_key_id: genesis.body.key_id,
            recovery_policy_id: None,
            recovery_policy_binding: None,
        },
        effective_at: 2_500,
        verify_until: None,
        reason: Some(EventReason::new("rotation cancelled").test_unwrap()),
        issued_at: 2_500,
    };
    let abort = SignedKeyLogEvent {
        authorizations: KeyLogAuthorizations::rotation(
            OldKeyAuthorization::sign(&abort_body, &fixture.old).test_unwrap(),
            NewKeyProofOfPossession::sign(&abort_body, &fixture.new).test_unwrap(),
        ),
        body: abort_body,
    };
    let abort_history = fixture.history(&[&genesis, &rotation, &abort], None);
    let state =
        KeyLogState::replay([&genesis, &rotation, &abort], &abort_history, &policy).test_unwrap();
    assert!(state.pending_rotation_key().is_none());
    assert_eq!(
        state.key(&rotation.body.key_id).test_unwrap().status,
        KeyStatus::Retired
    );

    let revoke_body = KeyLogEventBody {
        schema: KEY_LOG_EVENT_SCHEMA.to_string(),
        log_id: genesis.body.log_id.clone(),
        sequence: 2,
        event_id: EventId::new("event.revoke.old").test_unwrap(),
        previous_event_hash: Some(rotation.envelope_hash().test_unwrap()),
        authority_id: genesis.body.authority_id.clone(),
        key_id: genesis.body.key_id,
        algorithm: genesis.body.algorithm,
        public_key: genesis.body.public_key.clone(),
        operation: KeyLogOperation::Revoke,
        effective_at: 4_000,
        verify_until: None,
        reason: Some(EventReason::new("old key compromised").test_unwrap()),
        issued_at: 4_000,
    };
    let revoke = SignedKeyLogEvent {
        authorizations: KeyLogAuthorizations {
            old_key: Some(OldKeyAuthorization::sign(&revoke_body, &fixture.new).test_unwrap()),
            ..KeyLogAuthorizations::default()
        },
        body: revoke_body,
    };
    let revoke_history = fixture.history(&[&genesis, &rotation, &revoke], Some(1));
    let revoked =
        KeyLogState::replay([&genesis, &rotation, &revoke], &revoke_history, &policy).test_unwrap();
    assert_eq!(
        revoked.key(&genesis.body.key_id).test_unwrap().status,
        KeyStatus::Revoked
    );
}

#[test]
fn recovery_requires_distinct_threshold_authorizers_and_witnessed_activation() {
    let fixture = Fixture::new();
    let policy = fixture.policy();
    let genesis = fixture.genesis();
    let recovered = backend(4);
    let body = KeyLogEventBody {
        schema: KEY_LOG_EVENT_SCHEMA.to_string(),
        log_id: genesis.body.log_id.clone(),
        sequence: 1,
        event_id: EventId::new("event.recover.1").test_unwrap(),
        previous_event_hash: Some(genesis.envelope_hash().test_unwrap()),
        authority_id: genesis.body.authority_id.clone(),
        key_id: derive_key_id(recovered.algorithm(), &recovered.public_key()).test_unwrap(),
        algorithm: recovered.algorithm(),
        public_key: recovered.public_key(),
        operation: KeyLogOperation::Recover {
            previous_key_id: genesis.body.key_id,
            witness_roster_id: WitnessRosterId::new("roster.enterprise.v1").test_unwrap(),
            witness_roster_binding: policy.witness_roster_binding().test_unwrap(),
            recovery_policy_id: RecoveryPolicyId::new("recovery.enterprise.v1").test_unwrap(),
            recovery_policy_binding: policy.recovery_policy_binding().test_unwrap(),
        },
        effective_at: 2_000,
        verify_until: None,
        reason: Some(EventReason::new("threshold recovery").test_unwrap()),
        issued_at: 2_000,
    };
    let recovery = SignedKeyLogEvent {
        authorizations: KeyLogAuthorizations::recovery(vec![
            RecoveryAuthorization::sign(
                &body,
                RecoveryAuthorizerId::new("recovery.a").test_unwrap(),
                &fixture.recovery_a,
            )
            .test_unwrap(),
            RecoveryAuthorization::sign(
                &body,
                RecoveryAuthorizerId::new("recovery.b").test_unwrap(),
                &fixture.recovery_b,
            )
            .test_unwrap(),
        ]),
        body,
    };
    let history = fixture.history(&[&genesis, &recovery], Some(1));
    let state = KeyLogState::replay([&genesis, &recovery], &history, &policy).test_unwrap();
    assert_eq!(
        state.active_signing_key().test_unwrap().key_id,
        recovery.body.key_id
    );
    assert_eq!(
        state.key(&genesis.body.key_id).test_unwrap().status,
        KeyStatus::Revoked
    );

    let mut oversized = recovery;
    oversized.authorizations.recovery =
        vec![oversized.authorizations.recovery[0].clone(); MAX_RECOVERY_AUTHORIZATIONS + 1];
    let oversized_history = fixture.history(&[&genesis, &oversized], None);
    assert!(KeyLogState::replay([&genesis, &oversized], &oversized_history, &policy).is_err());
}

#[test]
fn complete_history_and_replay_reject_malformed_sequences_and_role_key_overlap() {
    let fixture = Fixture::new();
    let policy = fixture.policy();
    let genesis = fixture.genesis();
    let rotation = fixture.rotation(&genesis);

    let overlapping_policy = KeyLogPolicy::new(KeyLogPolicyConfig {
        log_id: genesis.body.log_id.clone(),
        authority_id: genesis.body.authority_id.clone(),
        bootstrap_key: fixture.bootstrap.public_key(),
        operator_key: fixture.old.public_key(),
        witness_roster_id: WitnessRosterId::new("roster.enterprise.v1").test_unwrap(),
        witness_keys: BTreeMap::from([(
            WitnessId::new("witness.a").test_unwrap(),
            fixture.witness_a.public_key(),
        )]),
        recovery_policy_id: RecoveryPolicyId::new("recovery.enterprise.v1").test_unwrap(),
        recovery_keys: BTreeMap::new(),
        recovery_threshold: 0,
        max_checkpoint_future_skew: 100,
    });
    assert!(overlapping_policy.is_ok());
    let history = fixture.history(&[&genesis], None);
    assert!(KeyLogState::replay([&genesis], &history, &overlapping_policy.test_unwrap()).is_err());

    let duplicate_role_policy = KeyLogPolicy::new(KeyLogPolicyConfig {
        log_id: genesis.body.log_id.clone(),
        authority_id: genesis.body.authority_id.clone(),
        bootstrap_key: fixture.bootstrap.public_key(),
        operator_key: fixture.operator.public_key(),
        witness_roster_id: WitnessRosterId::new("roster.enterprise.v1").test_unwrap(),
        witness_keys: BTreeMap::from([(
            WitnessId::new("witness.operator").test_unwrap(),
            fixture.operator.public_key(),
        )]),
        recovery_policy_id: RecoveryPolicyId::new("recovery.enterprise.v1").test_unwrap(),
        recovery_keys: BTreeMap::new(),
        recovery_threshold: 0,
        max_checkpoint_future_skew: 100,
    });
    assert!(duplicate_role_policy.is_err());

    let mut lifecycle_overlap = fixture.rotation(&genesis);
    lifecycle_overlap.body.key_id = derive_key_id(
        fixture.witness_a.algorithm(),
        &fixture.witness_a.public_key(),
    )
    .test_unwrap();
    lifecycle_overlap.body.algorithm = fixture.witness_a.algorithm();
    lifecycle_overlap.body.public_key = fixture.witness_a.public_key();
    lifecycle_overlap.authorizations = KeyLogAuthorizations::rotation(
        OldKeyAuthorization::sign(&lifecycle_overlap.body, &fixture.old).test_unwrap(),
        NewKeyProofOfPossession::sign(&lifecycle_overlap.body, &fixture.witness_a).test_unwrap(),
    );
    let overlap_history = fixture.history(&[&genesis, &lifecycle_overlap], None);
    assert!(
        KeyLogState::replay([&genesis, &lifecycle_overlap], &overlap_history, &policy,).is_err()
    );

    for malformed in [
        {
            let mut event = rotation.clone();
            event.body.event_id = genesis.body.event_id.clone();
            event.authorizations = KeyLogAuthorizations::rotation(
                OldKeyAuthorization::sign(&event.body, &fixture.old).test_unwrap(),
                NewKeyProofOfPossession::sign(&event.body, &fixture.new).test_unwrap(),
            );
            event
        },
        {
            let mut event = rotation.clone();
            event.body.sequence = 2;
            event
        },
        {
            let mut event = rotation;
            event.body.issued_at = 999;
            event.body.effective_at = 999;
            event.authorizations = KeyLogAuthorizations::rotation(
                OldKeyAuthorization::sign(&event.body, &fixture.old).test_unwrap(),
                NewKeyProofOfPossession::sign(&event.body, &fixture.new).test_unwrap(),
            );
            event
        },
    ] {
        let events = vec![genesis.clone(), malformed.clone()];
        let checkpoints = fixture.checkpoints(&[&genesis, &malformed], None);
        if let Ok(history) =
            WitnessedActivationSet::verify_complete(&events, &checkpoints, &[], &policy)
        {
            assert!(KeyLogState::replay([&genesis, &malformed], &history, &policy).is_err());
        }
    }

    let first = KeyLogState::replay([&genesis], &history, &policy).test_unwrap();
    let second = KeyLogState::replay([&genesis], &history, &policy).test_unwrap();
    assert_eq!(first, second);
    assert!(first
        .key(&derive_key_id(backend(99).algorithm(), &backend(99).public_key()).test_unwrap())
        .is_err());
}
