use chio_test_support::prelude::*;

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use chio_core_types::{Ed25519Backend, Keypair, SigningBackend};
use chio_keyring::{
    derive_key_id, durable_storage_identity, AuthorityId, BootstrapAuthorization, CheckpointGossip,
    EventId, EventReason, KeyLogAuditMonitor, KeyLogAuthorizations, KeyLogCheckpointBody,
    KeyLogEventBody, KeyLogOperation, KeyLogPolicy, KeyLogPolicyConfig, KeyLogSyncResponse,
    KeyringError, LogId, NewKeyProofOfPossession, OldKeyAuthorization, RecoveryPolicyId,
    SignedKeyActivationCommit, SignedKeyLogCheckpoint, SignedKeyLogEvent, SigningTopology,
    SqliteKeyLogStore, SqliteKeyLogWitness, SqlitePinnedKeyLogVerifier, WitnessId, WitnessRosterId,
    WitnessSignature, KEY_LOG_EVENT_SCHEMA, MAX_SYNC_ITEMS,
};

mod support;

use support::{private_tempdir, trusted_temp_path};

fn backend(seed: u8) -> Ed25519Backend {
    Ed25519Backend::new(Keypair::from_seed(&[seed; 32]))
}

struct FixedClock(u64);

impl chio_security_types::clock::Clock for FixedClock {
    fn read(
        &self,
    ) -> core::result::Result<
        chio_security_types::clock::ClockReading,
        chio_security_types::clock::ClockError,
    > {
        let value = self.0;
        chio_security_types::clock::Clock::read(
            &chio_security_types::clock::FixedClock::from_millis(value),
        )
    }
}

struct Fixture {
    bootstrap: Ed25519Backend,
    operator: Ed25519Backend,
    old: Ed25519Backend,
    new: Ed25519Backend,
    witnesses: [Ed25519Backend; 3],
    policy: KeyLogPolicy,
}

impl Fixture {
    fn new() -> Self {
        Self::with_log_id("log.witness.test")
    }

    fn with_log_id(log_id: &str) -> Self {
        let bootstrap = backend(1);
        let operator = backend(10);
        let old = backend(2);
        let new = backend(3);
        let witnesses = [backend(20), backend(21), backend(22)];
        let policy = KeyLogPolicy::new(KeyLogPolicyConfig {
            log_id: LogId::new(log_id).test_unwrap(),
            authority_id: AuthorityId::new("authority.witness.test").test_unwrap(),
            bootstrap_key: bootstrap.public_key(),
            operator_key: operator.public_key(),
            witness_roster_id: WitnessRosterId::new("roster.witness.v1").test_unwrap(),
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
            recovery_policy_id: RecoveryPolicyId::new("recovery.witness.v1").test_unwrap(),
            recovery_keys: BTreeMap::new(),
            recovery_threshold: 0,
            max_checkpoint_future_skew: 100,
        })
        .test_unwrap();
        Self {
            bootstrap,
            operator,
            old,
            new,
            witnesses,
            policy,
        }
    }

    fn genesis(&self) -> SignedKeyLogEvent {
        let body = KeyLogEventBody {
            schema: KEY_LOG_EVENT_SCHEMA.to_string(),
            log_id: self.policy.log_id().clone(),
            sequence: 0,
            event_id: EventId::new("event.genesis").test_unwrap(),
            previous_event_hash: None,
            authority_id: self.policy.authority_id().clone(),
            key_id: derive_key_id(self.old.algorithm(), &self.old.public_key()).test_unwrap(),
            algorithm: self.old.algorithm(),
            public_key: self.old.public_key(),
            operation: KeyLogOperation::Genesis,
            effective_at: 1_000,
            verify_until: None,
            reason: Some(EventReason::new("initial key").test_unwrap()),
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
                witness_roster_id: WitnessRosterId::new("roster.witness.v1").test_unwrap(),
                witness_roster_binding: self.policy.witness_roster_binding().test_unwrap(),
            },
            effective_at: 2_000,
            verify_until: Some(9_000),
            reason: Some(EventReason::new("rotation").test_unwrap()),
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

    fn store(&self, path: &Path) -> Arc<SqliteKeyLogStore> {
        Arc::new(
            SqliteKeyLogStore::open_with_clock(
                path,
                self.policy.clone(),
                SigningTopology::LocalSingleWriter,
                Arc::new(FixedClock(5_000)),
            )
            .test_unwrap(),
        )
    }

    fn witness(&self, path: &Path, index: usize) -> SqliteKeyLogWitness {
        let witness_id = WitnessId::new(format!(
            "witness.{}",
            char::from(b'a' + u8::try_from(index).test_unwrap())
        ))
        .test_unwrap();
        if path.exists() {
            SqliteKeyLogWitness::open(
                path,
                self.policy.clone(),
                witness_id,
                Box::new(self.witnesses[index].clone()),
                Arc::new(FixedClock(5_000)),
            )
            .test_unwrap()
        } else {
            SqliteKeyLogWitness::provision(
                path,
                self.policy.clone(),
                witness_id,
                Box::new(self.witnesses[index].clone()),
                Arc::new(FixedClock(5_000)),
            )
            .test_unwrap()
        }
    }
}

fn witness_checkpoint(
    store: &SqliteKeyLogStore,
    checkpoint: &SignedKeyLogCheckpoint,
    witnesses: &[&SqliteKeyLogWitness],
) {
    for witness in witnesses {
        let response = store
            .synchronization_response(witness.pin().test_unwrap().as_ref())
            .test_unwrap();
        let signature = witness.sign_candidate(checkpoint, &response).test_unwrap();
        store
            .store_witness_signature(&checkpoint.checkpoint_hash().test_unwrap(), &signature)
            .test_unwrap();
    }
}

#[test]
fn durable_witness_prevents_restart_double_sign_and_records_gossip_conflict() {
    let directory = private_tempdir().test_unwrap();
    let fixture = Fixture::new();
    let store = fixture.store(&trusted_temp_path(&directory, "operator.sqlite"));
    let genesis = fixture.genesis();
    let checkpoint = store
        .append_event(&genesis, &fixture.operator)
        .test_unwrap();
    let witness_path = trusted_temp_path(&directory, "witness-a.sqlite");
    let witness = fixture.witness(&witness_path, 0);
    let response = store.synchronization_response(None).test_unwrap();
    let first = witness.sign_candidate(&checkpoint, &response).test_unwrap();
    drop(witness);

    let reopened = fixture.witness(&witness_path, 0);
    let retry = reopened
        .sign_candidate(&checkpoint, &response)
        .test_unwrap();
    assert_eq!(retry, first);
    assert_eq!(reopened.pin().test_unwrap().test_unwrap().tree_size, 1);

    let mut fork_body = checkpoint.body.clone();
    fork_body.root_hash = chio_core_types::sha256(b"fork");
    let fork = SignedKeyLogCheckpoint::sign(fork_body, &fixture.operator).test_unwrap();
    let mut conflicting_response = response.clone();
    conflicting_response.checkpoints[0] = fork.clone();
    assert!(matches!(
        reopened.sign_candidate(&checkpoint, &conflicting_response),
        Err(KeyringError::EquivocationDetected)
    ));
    assert_eq!(reopened.conflicts().test_unwrap().len(), 1);

    let gossip = CheckpointGossip {
        checkpoint: fork.clone(),
        witness_signature: WitnessSignature::sign(
            &fork,
            WitnessId::new("witness.b").test_unwrap(),
            &fixture.witnesses[1],
        )
        .test_unwrap(),
    };
    assert!(matches!(
        reopened.import_gossip(&gossip),
        Err(KeyringError::EquivocationDetected)
    ));
    assert!(!reopened.conflicts().test_unwrap().is_empty());
}

#[test]
fn authenticated_unseen_gossip_is_durable_for_witness_and_verifier() {
    let directory = private_tempdir().test_unwrap();
    let fixture = Fixture::new();
    let store = fixture.store(&trusted_temp_path(&directory, "operator.sqlite"));
    let checkpoint = store
        .append_event(&fixture.genesis(), &fixture.operator)
        .test_unwrap();
    let gossip = CheckpointGossip {
        checkpoint: checkpoint.clone(),
        witness_signature: WitnessSignature::sign(
            &checkpoint,
            WitnessId::new("witness.b").test_unwrap(),
            &fixture.witnesses[1],
        )
        .test_unwrap(),
    };

    let witness_path = trusted_temp_path(&directory, "gossip-witness.sqlite");
    let witness = fixture.witness(&witness_path, 0);
    witness.import_gossip(&gossip).test_unwrap();
    assert_eq!(
        witness.gossip_observations().test_unwrap(),
        vec![gossip.clone()]
    );
    drop(witness);
    assert_eq!(
        fixture
            .witness(&witness_path, 0)
            .gossip_observations()
            .test_unwrap(),
        vec![gossip.clone()]
    );

    let verifier_path = trusted_temp_path(&directory, "gossip-verifier.sqlite");
    let verifier = SqlitePinnedKeyLogVerifier::provision(
        &verifier_path,
        fixture.policy.clone(),
        Arc::new(FixedClock(5_000)),
    )
    .test_unwrap();
    verifier.import_gossip(&gossip).test_unwrap();
    assert_eq!(
        verifier.gossip_observations().test_unwrap(),
        vec![gossip.clone()]
    );
    drop(verifier);
    assert_eq!(
        SqlitePinnedKeyLogVerifier::open(
            &verifier_path,
            fixture.policy,
            Arc::new(FixedClock(5_000)),
        )
        .test_unwrap()
        .gossip_observations()
        .test_unwrap(),
        vec![gossip]
    );
}

#[test]
fn review_witness_refuses_candidate_conflicting_with_retained_gossip() {
    let directory = private_tempdir().test_unwrap();
    let fixture = Fixture::new();
    let store = fixture.store(&trusted_temp_path(
        &directory,
        "gossip-first-operator.sqlite",
    ));
    let checkpoint = store
        .append_event(&fixture.genesis(), &fixture.operator)
        .test_unwrap();
    let mut fork_body = checkpoint.body.clone();
    fork_body.issued_at += 1;
    let fork = SignedKeyLogCheckpoint::sign(fork_body, &fixture.operator).test_unwrap();
    let gossip = CheckpointGossip {
        witness_signature: WitnessSignature::sign(
            &fork,
            WitnessId::new("witness.b").test_unwrap(),
            &fixture.witnesses[1],
        )
        .test_unwrap(),
        checkpoint: fork.clone(),
    };
    let path = trusted_temp_path(&directory, "gossip-first-witness.sqlite");
    let witness = fixture.witness(&path, 0);
    witness.import_gossip(&gossip).test_unwrap();
    let response = store.synchronization_response(None).test_unwrap();
    assert!(matches!(
        witness.sign_candidate(&checkpoint, &response),
        Err(KeyringError::EquivocationDetected)
    ));
    assert!(witness.pin().test_unwrap().is_none());
    assert!(witness.gossip_for_sequence(0).test_unwrap().is_none());
    assert_eq!(
        witness.gossip_observations().test_unwrap(),
        vec![gossip.clone()]
    );
    let conflicts = witness.conflicts().test_unwrap();
    assert_eq!(conflicts.len(), 1);
    assert_eq!(
        conflicts[0].first.checkpoint_hash().test_unwrap(),
        fork.checkpoint_hash().test_unwrap()
    );
    assert_eq!(
        conflicts[0].conflicting.checkpoint_hash().test_unwrap(),
        checkpoint.checkpoint_hash().test_unwrap()
    );
    assert_eq!(conflicts[0].detected_at, 5_000);
    drop(witness);
    let reopened = fixture.witness(&path, 0);
    assert!(matches!(
        reopened.sign_candidate(&checkpoint, &response),
        Err(KeyringError::EquivocationDetected)
    ));
    assert_eq!(reopened.conflicts().test_unwrap(), conflicts);
    assert_eq!(reopened.gossip_observations().test_unwrap(), vec![gossip]);
}

#[test]
fn review_witness_refuses_response_history_conflicting_with_retained_gossip() {
    let directory = private_tempdir().test_unwrap();
    let fixture = Fixture::new();
    let store = fixture.store(&trusted_temp_path(
        &directory,
        "gossip-range-operator.sqlite",
    ));
    let genesis = fixture.genesis();
    let first = store
        .append_event(&genesis, &fixture.operator)
        .test_unwrap();
    let candidate = store
        .append_event(&fixture.rotation(&genesis), &fixture.operator)
        .test_unwrap();
    let mut fork_body = first.body.clone();
    fork_body.issued_at += 1;
    let fork = SignedKeyLogCheckpoint::sign(fork_body, &fixture.operator).test_unwrap();
    let gossip = CheckpointGossip {
        witness_signature: WitnessSignature::sign(
            &fork,
            WitnessId::new("witness.b").test_unwrap(),
            &fixture.witnesses[1],
        )
        .test_unwrap(),
        checkpoint: fork,
    };
    let witness = fixture.witness(
        &trusted_temp_path(&directory, "gossip-range-witness.sqlite"),
        0,
    );
    witness.import_gossip(&gossip).test_unwrap();
    let response = store.synchronization_response(None).test_unwrap();
    assert!(matches!(
        witness.sign_candidate(&candidate, &response),
        Err(KeyringError::EquivocationDetected)
    ));
    assert!(witness.pin().test_unwrap().is_none());
    assert!(witness.gossip_for_sequence(1).test_unwrap().is_none());
    let conflicts = witness.conflicts().test_unwrap();
    assert_eq!(conflicts.len(), 1);
    assert_eq!(
        conflicts[0].conflicting.checkpoint_hash().test_unwrap(),
        first.checkpoint_hash().test_unwrap()
    );
    assert_eq!(witness.gossip_observations().test_unwrap(), vec![gossip]);
}

#[test]
fn review_witness_refuses_tree_size_fork_in_retained_gossip() {
    let directory = private_tempdir().test_unwrap();
    let fixture = Fixture::new();
    let store = fixture.store(&trusted_temp_path(
        &directory,
        "gossip-size-operator.sqlite",
    ));
    let checkpoint = store
        .append_event(&fixture.genesis(), &fixture.operator)
        .test_unwrap();
    let mut fork_body = checkpoint.body.clone();
    fork_body.checkpoint_sequence = 9;
    let fork = SignedKeyLogCheckpoint::sign(fork_body, &fixture.operator).test_unwrap();
    let gossip = CheckpointGossip {
        witness_signature: WitnessSignature::sign(
            &fork,
            WitnessId::new("witness.b").test_unwrap(),
            &fixture.witnesses[1],
        )
        .test_unwrap(),
        checkpoint: fork,
    };
    let witness = fixture.witness(
        &trusted_temp_path(&directory, "gossip-size-witness.sqlite"),
        0,
    );
    witness.import_gossip(&gossip).test_unwrap();
    let response = store.synchronization_response(None).test_unwrap();
    assert!(matches!(
        witness.sign_candidate(&checkpoint, &response),
        Err(KeyringError::EquivocationDetected)
    ));
    assert!(witness.pin().test_unwrap().is_none());
    assert_eq!(
        witness.conflicts().test_unwrap()[0].kind,
        chio_keyring::CheckpointConflictKind::TreeSize
    );
}

#[test]
fn review_witness_startup_rejects_gossip_conflicting_with_own_checkpoint() {
    let directory = private_tempdir().test_unwrap();
    let fixture = Fixture::new();
    let store = fixture.store(&trusted_temp_path(
        &directory,
        "gossip-startup-operator.sqlite",
    ));
    let checkpoint = store
        .append_event(&fixture.genesis(), &fixture.operator)
        .test_unwrap();
    let response = store.synchronization_response(None).test_unwrap();
    let path = trusted_temp_path(&directory, "gossip-startup-witness.sqlite");
    let witness = fixture.witness(&path, 0);
    witness.sign_candidate(&checkpoint, &response).test_unwrap();
    drop(witness);
    let mut fork_body = checkpoint.body.clone();
    fork_body.issued_at += 1;
    let fork = SignedKeyLogCheckpoint::sign(fork_body, &fixture.operator).test_unwrap();
    let gossip = CheckpointGossip {
        witness_signature: WitnessSignature::sign(
            &fork,
            WitnessId::new("witness.b").test_unwrap(),
            &fixture.witnesses[1],
        )
        .test_unwrap(),
        checkpoint: fork,
    };
    // Simulate an older store retaining authentic gossip alongside its own
    // conflicting decision. Both signatures are real deterministic fixtures.
    let connection = rusqlite::Connection::open(&path).test_unwrap();
    connection.execute(
        "INSERT INTO witness_gossip (checkpoint_hash, witness_id, checkpoint_sequence, tree_size, canonical_gossip) VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![gossip.checkpoint.checkpoint_hash().test_unwrap().to_string(), "witness.b", 0, 1, chio_core_types::canonical_json_bytes(&gossip).test_unwrap()],
    ).test_unwrap();
    drop(connection);
    assert!(matches!(
        SqliteKeyLogWitness::open(
            &path,
            fixture.policy,
            WitnessId::new("witness.a").test_unwrap(),
            Box::new(fixture.witnesses[0].clone()),
            Arc::new(FixedClock(5_000)),
        ),
        Err(KeyringError::EquivocationDetected)
    ));
    let connection = rusqlite::Connection::open(&path).test_unwrap();
    let gossip_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM witness_gossip", [], |row| row.get(0))
        .test_unwrap();
    let conflict_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM witness_conflicts", [], |row| {
            row.get(0)
        })
        .test_unwrap();
    assert_eq!(gossip_count, 1);
    assert_eq!(conflict_count, 1);
}

#[test]
fn review_witness_checks_all_retained_signed_gossip_before_replaying_decision() {
    let directory = private_tempdir().test_unwrap();
    let fixture = Fixture::new();
    let store = fixture.store(&trusted_temp_path(&directory, "gossip-all-operator.sqlite"));
    let checkpoint = store
        .append_event(&fixture.genesis(), &fixture.operator)
        .test_unwrap();
    let response = store.synchronization_response(None).test_unwrap();
    let path = trusted_temp_path(&directory, "gossip-all-witness.sqlite");
    let witness = fixture.witness(&path, 0);
    witness.sign_candidate(&checkpoint, &response).test_unwrap();
    let accepted_pin = witness.pin().test_unwrap();
    let checkpoint_hash = checkpoint.checkpoint_hash().test_unwrap().to_string();
    // Make the first indexed observation agree with the decided checkpoint.
    // A SELECT ... LIMIT 1 must not hide a later authentic disagreement.
    let fork = (1..=100)
        .map(|offset| {
            let mut body = checkpoint.body.clone();
            body.issued_at += offset;
            SignedKeyLogCheckpoint::sign(body, &fixture.operator).test_unwrap()
        })
        .find(|candidate| candidate.checkpoint_hash().test_unwrap().to_string() > checkpoint_hash)
        .test_unwrap();
    let connection = rusqlite::Connection::open(&path).test_unwrap();
    let mut observations = Vec::new();
    for (signed, id, backend) in [
        (&checkpoint, "witness.b", &fixture.witnesses[1]),
        (&fork, "witness.c", &fixture.witnesses[2]),
    ] {
        let gossip = CheckpointGossip {
            checkpoint: signed.clone(),
            witness_signature: WitnessSignature::sign(
                signed,
                WitnessId::new(id).test_unwrap(),
                backend,
            )
            .test_unwrap(),
        };
        connection.execute(
            "INSERT INTO witness_gossip (checkpoint_hash, witness_id, checkpoint_sequence, tree_size, canonical_gossip) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![signed.checkpoint_hash().test_unwrap().to_string(), id, 0, 1, chio_core_types::canonical_json_bytes(&gossip).test_unwrap()],
        ).test_unwrap();
        observations.push(gossip);
    }
    drop(connection);
    assert!(matches!(
        witness.sign_candidate(&checkpoint, &response),
        Err(KeyringError::EquivocationDetected)
    ));
    assert_eq!(witness.pin().test_unwrap(), accepted_pin);
    assert_eq!(witness.gossip_observations().test_unwrap(), observations);
    assert_eq!(witness.conflicts().test_unwrap().len(), 1);
}

#[test]
fn review_witness_retains_conflicting_authenticated_gossip() {
    let directory = private_tempdir().test_unwrap();
    let fixture = Fixture::new();
    let store = fixture.store(&trusted_temp_path(
        &directory,
        "gossip-conflict-operator.sqlite",
    ));
    let checkpoint = store
        .append_event(&fixture.genesis(), &fixture.operator)
        .test_unwrap();
    let response = store.synchronization_response(None).test_unwrap();
    let witness = fixture.witness(
        &trusted_temp_path(&directory, "gossip-conflict-witness.sqlite"),
        0,
    );
    witness.sign_candidate(&checkpoint, &response).test_unwrap();
    let mut fork_body = checkpoint.body.clone();
    fork_body.issued_at += 1;
    let fork = SignedKeyLogCheckpoint::sign(fork_body, &fixture.operator).test_unwrap();
    let gossip = CheckpointGossip {
        witness_signature: WitnessSignature::sign(
            &fork,
            WitnessId::new("witness.b").test_unwrap(),
            &fixture.witnesses[1],
        )
        .test_unwrap(),
        checkpoint: fork,
    };
    assert!(matches!(
        witness.import_gossip(&gossip),
        Err(KeyringError::EquivocationDetected)
    ));
    assert_eq!(witness.gossip_observations().test_unwrap(), vec![gossip]);
    assert_eq!(witness.conflicts().test_unwrap().len(), 1);
}

#[test]
fn witness_restart_accepts_a_signed_multi_checkpoint_range() {
    let directory = private_tempdir().test_unwrap();
    let fixture = Fixture::new();
    let store = fixture.store(&trusted_temp_path(&directory, "operator.sqlite"));
    let genesis = fixture.genesis();
    store
        .append_event(&genesis, &fixture.operator)
        .test_unwrap();
    let rotation = fixture.rotation(&genesis);
    let rotation_checkpoint = store
        .append_event(&rotation, &fixture.operator)
        .test_unwrap();
    let witness_path = trusted_temp_path(&directory, "range-witness.sqlite");
    let witness = fixture.witness(&witness_path, 0);
    let response = store.synchronization_response(None).test_unwrap();
    assert_eq!(response.checkpoints.len(), 2);
    witness
        .sign_candidate(&rotation_checkpoint, &response)
        .test_unwrap();
    drop(witness);

    let reopened = fixture.witness(&witness_path, 0);
    assert_eq!(
        reopened
            .pin()
            .test_unwrap()
            .test_unwrap()
            .checkpoint_sequence,
        1
    );
}

#[test]
fn contiguous_sync_activation_fresh_verifier_and_monitor_preserve_pins() {
    let directory = private_tempdir().test_unwrap();
    let fixture = Fixture::new();
    let store = fixture.store(&trusted_temp_path(&directory, "operator.sqlite"));
    let witness_a = fixture.witness(&trusted_temp_path(&directory, "witness-a.sqlite"), 0);
    let witness_b = fixture.witness(&trusted_temp_path(&directory, "witness-b.sqlite"), 1);
    let genesis = fixture.genesis();
    let genesis_checkpoint = store
        .append_event(&genesis, &fixture.operator)
        .test_unwrap();
    witness_checkpoint(&store, &genesis_checkpoint, &[&witness_a, &witness_b]);

    let rotation = fixture.rotation(&genesis);
    let rotation_checkpoint = store
        .append_event(&rotation, &fixture.operator)
        .test_unwrap();
    witness_checkpoint(&store, &rotation_checkpoint, &[&witness_a, &witness_b]);
    let rotation_checkpoint = store.load_checkpoints().test_unwrap()[1].checkpoint.clone();
    store
        .activate_rotation(
            &rotation.body.event_id,
            &rotation_checkpoint.checkpoint_hash().test_unwrap(),
            &fixture.operator,
        )
        .test_unwrap();

    for witness in [&witness_a, &witness_b] {
        let response = store
            .synchronization_response(witness.pin().test_unwrap().as_ref())
            .test_unwrap();
        witness
            .sign_candidate(&rotation_checkpoint, &response)
            .test_unwrap();
        assert_eq!(witness.pin().test_unwrap().test_unwrap().signing_epoch, 1);
    }

    let verifier_path = trusted_temp_path(&directory, "verifier.sqlite");
    let verifier = SqlitePinnedKeyLogVerifier::provision(
        &verifier_path,
        fixture.policy.clone(),
        Arc::new(FixedClock(5_000)),
    )
    .test_unwrap();
    let full = store.synchronization_response(None).test_unwrap();
    let pin = verifier.apply_sync(&full).test_unwrap();
    assert_eq!(pin.tree_size, 2);
    assert_eq!(pin.signing_epoch, 1);
    drop(verifier);
    assert_eq!(
        SqlitePinnedKeyLogVerifier::open(
            &verifier_path,
            fixture.policy.clone(),
            Arc::new(FixedClock(5_000)),
        )
        .test_unwrap()
        .pin()
        .test_unwrap(),
        Some(pin.clone())
    );

    let monitor_a = KeyLogAuditMonitor::new(
        SqlitePinnedKeyLogVerifier::provision(
            trusted_temp_path(&directory, "monitor-a.sqlite"),
            fixture.policy.clone(),
            Arc::new(FixedClock(5_000)),
        )
        .test_unwrap(),
    );
    let monitor_b = KeyLogAuditMonitor::new(
        SqlitePinnedKeyLogVerifier::provision(
            trusted_temp_path(&directory, "monitor-b.sqlite"),
            fixture.policy.clone(),
            Arc::new(FixedClock(5_000)),
        )
        .test_unwrap(),
    );
    monitor_a.poll(&full).test_unwrap();
    monitor_b.poll(&full).test_unwrap();
    let accepted_pin = monitor_a.pin().test_unwrap();
    assert_eq!(monitor_b.pin().test_unwrap(), accepted_pin);

    let mut fork_body = rotation_checkpoint.body.clone();
    fork_body.root_hash = chio_core_types::sha256(b"operator-split-view");
    fork_body.issued_at = 1;
    let fork = SignedKeyLogCheckpoint::sign(fork_body, &fixture.operator).test_unwrap();
    let mut split_view = full.clone();
    split_view.checkpoints[1] = fork;
    assert!(matches!(
        monitor_a.poll(&split_view),
        Err(KeyringError::EquivocationDetected)
    ));
    let conflicts = monitor_a.conflicts().test_unwrap();
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].detected_at, 5_000);
    assert_eq!(monitor_a.pin().test_unwrap(), accepted_pin);

    let mut future_commit = full.activation_commits[0].body.clone();
    future_commit.committed_at = 5_101;
    let mut future_activation = full.clone();
    future_activation.activation_commits[0] =
        SignedKeyActivationCommit::sign(future_commit, &fixture.operator).test_unwrap();
    let future_verifier = SqlitePinnedKeyLogVerifier::provision(
        trusted_temp_path(&directory, "future-verifier.sqlite"),
        fixture.policy.clone(),
        Arc::new(FixedClock(5_000)),
    )
    .test_unwrap();
    assert!(future_verifier.apply_sync(&future_activation).is_err());
    assert!(future_verifier.pin().test_unwrap().is_none());

    let mut omitted = store
        .synchronization_response(accepted_pin.as_ref())
        .test_unwrap();
    omitted.base_checkpoint_hash = Some(chio_core_types::sha256(b"wrong-base"));
    assert!(monitor_a.poll(&omitted).is_err());
    assert!(monitor_b.poll(&omitted).is_err());
    assert_eq!(monitor_a.pin().test_unwrap(), accepted_pin);
    assert_eq!(monitor_b.pin().test_unwrap(), accepted_pin);
}

#[test]
fn omitted_envelope_and_stale_consistency_proof_do_not_advance_witness_pin() {
    let directory = private_tempdir().test_unwrap();
    let fixture = Fixture::new();
    let store = fixture.store(&trusted_temp_path(&directory, "operator.sqlite"));
    let witness = fixture.witness(&trusted_temp_path(&directory, "witness.sqlite"), 0);
    let genesis = fixture.genesis();
    let genesis_checkpoint = store
        .append_event(&genesis, &fixture.operator)
        .test_unwrap();
    let response = store.synchronization_response(None).test_unwrap();
    witness
        .sign_candidate(&genesis_checkpoint, &response)
        .test_unwrap();
    let original_pin = witness.pin().test_unwrap();

    let rotation = fixture.rotation(&genesis);
    let rotation_checkpoint = store
        .append_event(&rotation, &fixture.operator)
        .test_unwrap();
    let valid = store
        .synchronization_response(original_pin.as_ref())
        .test_unwrap();
    let mut omitted = valid.clone();
    omitted.event_envelopes.clear();
    assert!(witness
        .sign_candidate(&rotation_checkpoint, &omitted)
        .is_err());
    assert_eq!(witness.pin().test_unwrap(), original_pin);

    let mut stale = valid;
    stale
        .consistency_proof
        .as_mut()
        .test_unwrap()
        .audit_path
        .push(chio_core_types::Hash::zero());
    assert!(witness
        .sign_candidate(&rotation_checkpoint, &stale)
        .is_err());
    assert_eq!(witness.pin().test_unwrap(), original_pin);
}

#[test]
fn witness_rejects_checkpoint_beyond_configured_future_skew() {
    let directory = private_tempdir().test_unwrap();
    let fixture = Fixture::new();
    let store = fixture.store(&trusted_temp_path(&directory, "operator.sqlite"));
    let witness = fixture.witness(&trusted_temp_path(&directory, "future.sqlite"), 0);
    let genesis = fixture.genesis();
    let checkpoint = store
        .append_event(&genesis, &fixture.operator)
        .test_unwrap();
    let response = store.synchronization_response(None).test_unwrap();
    let future = SignedKeyLogCheckpoint::sign(
        KeyLogCheckpointBody {
            issued_at: 5_101,
            ..checkpoint.body
        },
        &fixture.operator,
    )
    .test_unwrap();
    assert!(witness.sign_candidate(&future, &response).is_err());
    assert!(witness.pin().test_unwrap().is_none());
}

#[test]
fn synchronization_deserialization_rejects_oversized_vectors_before_growth() {
    let json = serde_json::json!({
        "checkpoints": vec![serde_json::Value::Null; MAX_SYNC_ITEMS + 1],
        "event_envelopes": [],
    });
    assert!(serde_json::from_value::<KeyLogSyncResponse>(json).is_err());
}

#[test]
fn synchronization_deserialization_rejects_present_but_empty_activation_commits() {
    let json = serde_json::json!({
        "checkpoints": [],
        "event_envelopes": [],
        "activation_commits": [],
    });
    assert!(serde_json::from_value::<KeyLogSyncResponse>(json).is_err());
}

#[test]
fn synchronization_item_limit_cannot_emit_a_decoder_oversized_page() {
    let directory = private_tempdir().test_unwrap();
    let fixture = Fixture::new();
    let store = fixture.store(&trusted_temp_path(&directory, "operator.sqlite"));
    let event = fixture.genesis();
    let checkpoint = store.append_event(&event, &fixture.operator).test_unwrap();
    let mut response = store.synchronization_response(None).test_unwrap();
    response.event_envelopes = vec![event; MAX_SYNC_ITEMS];
    response.checkpoints = vec![checkpoint; MAX_SYNC_ITEMS];
    assert!(
        chio_core_types::canonical_json_bytes(&response)
            .test_unwrap()
            .len()
            > chio_keyring::MAX_CANONICAL_RECORD_BYTES
    );
    assert!(response.validate_bounds().is_err());
}

#[test]
fn witness_and_verifier_open_require_preprovisioned_durable_files() {
    let fixture = Fixture::new();
    let directory = private_tempdir().test_unwrap();
    let missing_witness = trusted_temp_path(&directory, "missing-witness.sqlite");
    assert!(SqliteKeyLogWitness::open(
        &missing_witness,
        fixture.policy.clone(),
        WitnessId::new("witness.a").test_unwrap(),
        Box::new(fixture.witnesses[0].clone()),
        Arc::new(FixedClock(5_000)),
    )
    .is_err());
    assert!(!missing_witness.exists());

    let missing_verifier = trusted_temp_path(&directory, "missing-verifier.sqlite");
    assert!(SqlitePinnedKeyLogVerifier::open(
        &missing_verifier,
        fixture.policy.clone(),
        Arc::new(FixedClock(5_000)),
    )
    .is_err());
    assert!(!missing_verifier.exists());

    assert!(SqliteKeyLogWitness::open(
        ":memory:",
        fixture.policy.clone(),
        WitnessId::new("witness.a").test_unwrap(),
        Box::new(fixture.witnesses[0].clone()),
        Arc::new(FixedClock(5_000)),
    )
    .is_err());
    assert!(SqlitePinnedKeyLogVerifier::open(
        ":memory:",
        fixture.policy,
        Arc::new(FixedClock(5_000)),
    )
    .is_err());
}

#[cfg(unix)]
#[test]
fn witness_and_audit_storage_identities_survive_database_path_swap() {
    use std::os::unix::fs::OpenOptionsExt;

    let fixture = Fixture::new();
    let directory = private_tempdir().test_unwrap();
    let witness_path = trusted_temp_path(&directory, "witness.sqlite");
    let witness_displaced = trusted_temp_path(&directory, "witness-original.sqlite");
    let verifier_path = trusted_temp_path(&directory, "audit.sqlite");
    let verifier_displaced = trusted_temp_path(&directory, "audit-original.sqlite");
    let witness = SqliteKeyLogWitness::provision(
        &witness_path,
        fixture.policy.clone(),
        WitnessId::new("witness.a").test_unwrap(),
        Box::new(fixture.witnesses[0].clone()),
        Arc::new(FixedClock(5_000)),
    )
    .test_unwrap();
    let verifier = SqlitePinnedKeyLogVerifier::provision(
        &verifier_path,
        fixture.policy,
        Arc::new(FixedClock(5_000)),
    )
    .test_unwrap();
    let witness_identity = witness.storage_identity();
    let verifier_identity = verifier.storage_identity();
    assert_ne!(witness_identity, verifier_identity);

    std::fs::rename(&witness_path, &witness_displaced).test_unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&witness_path)
        .test_unwrap();
    std::fs::rename(&verifier_path, &verifier_displaced).test_unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&verifier_path)
        .test_unwrap();

    assert_eq!(witness.storage_identity(), witness_identity);
    assert_eq!(verifier.storage_identity(), verifier_identity);
    assert_ne!(
        durable_storage_identity(&witness_path).test_unwrap(),
        witness_identity
    );
    assert_ne!(
        durable_storage_identity(&verifier_path).test_unwrap(),
        verifier_identity
    );
}

#[test]
fn witness_refuses_to_sign_a_candidate_that_conflicts_with_retained_gossip() {
    let directory = private_tempdir().test_unwrap();
    let fixture = Fixture::new();
    let store = fixture.store(&trusted_temp_path(&directory, "operator.sqlite"));
    let checkpoint = store
        .append_event(&fixture.genesis(), &fixture.operator)
        .test_unwrap();
    let response = store.synchronization_response(None).test_unwrap();

    let mut fork_body = checkpoint.body.clone();
    fork_body.root_hash = chio_core_types::sha256(b"fork");
    let fork = SignedKeyLogCheckpoint::sign(fork_body, &fixture.operator).test_unwrap();
    let gossip = CheckpointGossip {
        checkpoint: fork.clone(),
        witness_signature: WitnessSignature::sign(
            &fork,
            WitnessId::new("witness.b").test_unwrap(),
            &fixture.witnesses[1],
        )
        .test_unwrap(),
    };

    let witness = fixture.witness(&trusted_temp_path(&directory, "lagging-witness.sqlite"), 0);
    witness.import_gossip(&gossip).test_unwrap();
    assert!(matches!(
        witness.sign_candidate(&checkpoint, &response),
        Err(KeyringError::EquivocationDetected)
    ));
    assert_eq!(witness.conflicts().test_unwrap().len(), 1);
}

#[test]
fn replaying_a_decided_candidate_with_newer_checkpoints_keeps_the_witness_restartable() {
    let directory = private_tempdir().test_unwrap();
    let fixture = Fixture::new();
    let store = fixture.store(&trusted_temp_path(&directory, "operator.sqlite"));
    let genesis = fixture.genesis();
    let decided = store
        .append_event(&genesis, &fixture.operator)
        .test_unwrap();
    let witness_path = trusted_temp_path(&directory, "decided-witness.sqlite");
    let witness = fixture.witness(&witness_path, 0);
    let first = witness
        .sign_candidate(
            &decided,
            &store.synchronization_response(None).test_unwrap(),
        )
        .test_unwrap();

    store
        .append_event(&fixture.rotation(&genesis), &fixture.operator)
        .test_unwrap();
    let newer = store
        .synchronization_response(witness.pin().test_unwrap().as_ref())
        .test_unwrap();
    assert!(!newer.checkpoints.is_empty());
    let replay = witness.sign_candidate(&decided, &newer).test_unwrap();
    assert_eq!(replay, first);
    drop(witness);

    let reopened = fixture.witness(&witness_path, 0);
    assert_eq!(
        reopened
            .pin()
            .test_unwrap()
            .test_unwrap()
            .checkpoint_sequence,
        0
    );
}

struct NamespaceFixture {
    a: Fixture,
    a_store: Arc<SqliteKeyLogStore>,
    a_head: SignedKeyLogCheckpoint,
    b_head: SignedKeyLogCheckpoint,
    b_response: KeyLogSyncResponse,
    b_gossip: CheckpointGossip,
}

impl NamespaceFixture {
    fn new(directory: &tempfile::TempDir) -> Self {
        let a = Fixture::with_log_id("log.namespace.a");
        let b = Fixture::with_log_id("log.namespace.b");
        assert_eq!(
            a.policy.operator_public_key(),
            b.policy.operator_public_key()
        );
        assert_eq!(
            a.policy.witness_public_keys(),
            b.policy.witness_public_keys()
        );
        let a_store = a.store(&trusted_temp_path(directory, "namespace-a-operator.sqlite"));
        let b_store = b.store(&trusted_temp_path(directory, "namespace-b-operator.sqlite"));
        let a_checkpoint = a_store
            .append_event(&a.genesis(), &a.operator)
            .test_unwrap();
        let b_checkpoint = b_store
            .append_event(&b.genesis(), &b.operator)
            .test_unwrap();
        let a_witnesses = [
            a.witness(&trusted_temp_path(directory, "namespace-a-peer1.sqlite"), 0),
            a.witness(&trusted_temp_path(directory, "namespace-a-peer2.sqlite"), 1),
        ];
        let b_witnesses = [
            b.witness(&trusted_temp_path(directory, "namespace-b-peer1.sqlite"), 0),
            b.witness(&trusted_temp_path(directory, "namespace-b-peer2.sqlite"), 1),
        ];
        witness_checkpoint(&a_store, &a_checkpoint, &[&a_witnesses[0], &a_witnesses[1]]);
        witness_checkpoint(&b_store, &b_checkpoint, &[&b_witnesses[0], &b_witnesses[1]]);
        Self {
            a,
            a_head: a_store
                .load_checkpoints()
                .test_unwrap()
                .pop()
                .test_unwrap()
                .checkpoint,
            b_head: b_store
                .load_checkpoints()
                .test_unwrap()
                .pop()
                .test_unwrap()
                .checkpoint,
            b_response: b_store.synchronization_response(None).test_unwrap(),
            b_gossip: b_witnesses[1]
                .gossip_for_sequence(0)
                .test_unwrap()
                .test_unwrap(),
            a_store,
        }
    }

    fn witness(&self, directory: &tempfile::TempDir) -> SqliteKeyLogWitness {
        let witness = self.a.witness(
            &trusted_temp_path(directory, "namespace-target-witness.sqlite"),
            0,
        );
        witness
            .sign_candidate(
                &self.a_head,
                &self.a_store.synchronization_response(None).test_unwrap(),
            )
            .test_unwrap();
        witness
    }

    fn verifier(&self, directory: &tempfile::TempDir) -> SqlitePinnedKeyLogVerifier {
        let verifier = SqlitePinnedKeyLogVerifier::provision(
            trusted_temp_path(directory, "namespace-target-verifier.sqlite"),
            self.a.policy.clone(),
            Arc::new(FixedClock(5_000)),
        )
        .test_unwrap();
        verifier
            .apply_sync(&self.a_store.synchronization_response(None).test_unwrap())
            .test_unwrap();
        verifier
    }

    fn retain_foreign_archive(&self, path: &Path, gossip_table: &str, conflict_table: &str) {
        let connection = rusqlite::Connection::open(path).test_unwrap();
        connection.execute(
            &format!("INSERT INTO {gossip_table} (checkpoint_hash, witness_id, checkpoint_sequence, tree_size, canonical_gossip) VALUES (?1, ?2, 0, 1, ?3)"),
            rusqlite::params![self.b_gossip.checkpoint.checkpoint_hash().test_unwrap().to_string(), self.b_gossip.witness_signature.witness_id.as_str(), chio_core_types::canonical_json_bytes(&self.b_gossip).test_unwrap()],
        ).test_unwrap();
        let false_conflict = chio_keyring::CheckpointEquivocationEvidence {
            schema: chio_keyring::CHECKPOINT_EQUIVOCATION_SCHEMA.to_string(),
            kind: chio_keyring::CheckpointConflictKind::CheckpointSequence,
            first: self.a_head.clone(),
            conflicting: self.b_head.clone(),
            detected_at: 5_000,
        };
        connection.execute(
            &format!("INSERT INTO {conflict_table} (conflict_hash, canonical_evidence) VALUES (?1, ?2)"),
            rusqlite::params![false_conflict.evidence_hash().test_unwrap().to_string(), chio_core_types::canonical_json_bytes(&false_conflict).test_unwrap()],
        ).test_unwrap();
    }

    fn assert_foreign_archive_preserved(
        &self,
        path: &Path,
        gossip_table: &str,
        conflict_table: &str,
    ) {
        let connection = rusqlite::Connection::open(path).test_unwrap();
        let canonical: Vec<u8> = connection
            .query_row(
                &format!("SELECT canonical_gossip FROM {gossip_table}"),
                [],
                |row| row.get(0),
            )
            .test_unwrap();
        assert_eq!(
            canonical,
            chio_core_types::canonical_json_bytes(&self.b_gossip).test_unwrap()
        );
        let count: i64 = connection
            .query_row(
                &format!("SELECT COUNT(*) FROM {conflict_table}"),
                [],
                |row| row.get(0),
            )
            .test_unwrap();
        assert_eq!(count, 1);
    }
}

#[test]
fn review_namespace_witness_rejects_foreign_gossip_before_retention() {
    let directory = private_tempdir().test_unwrap();
    let fixture = NamespaceFixture::new(&directory);
    let witness = fixture.witness(&directory);
    let pin = witness.pin().test_unwrap();
    assert!(matches!(
        witness.import_gossip(&fixture.b_gossip),
        Err(KeyringError::IdentityMismatch)
    ));
    assert!(witness.gossip_observations().test_unwrap().is_empty());
    assert!(witness.conflicts().test_unwrap().is_empty());
    assert_eq!(witness.pin().test_unwrap(), pin);
    witness
        .sign_candidate(
            &fixture.a_head,
            &fixture.a_store.synchronization_response(None).test_unwrap(),
        )
        .test_unwrap();
}

#[test]
fn review_namespace_witness_rejects_foreign_candidate_before_conflict() {
    let directory = private_tempdir().test_unwrap();
    let fixture = NamespaceFixture::new(&directory);
    let witness = fixture.witness(&directory);
    let pin = witness.pin().test_unwrap();
    assert!(matches!(
        witness.sign_candidate(&fixture.b_head, &fixture.b_response),
        Err(KeyringError::IdentityMismatch)
    ));
    assert!(witness.conflicts().test_unwrap().is_empty());
    assert_eq!(witness.pin().test_unwrap(), pin);
}

#[test]
fn review_namespace_witness_rejects_foreign_response_before_conflict() {
    let directory = private_tempdir().test_unwrap();
    let fixture = NamespaceFixture::new(&directory);
    let witness = fixture.witness(&directory);
    let pin = witness.pin().test_unwrap();
    assert!(matches!(
        witness.sign_candidate(&fixture.a_head, &fixture.b_response),
        Err(KeyringError::IdentityMismatch)
    ));
    assert!(witness.conflicts().test_unwrap().is_empty());
    assert_eq!(witness.pin().test_unwrap(), pin);
}

#[test]
fn review_namespace_witness_reopens_with_foreign_archive_without_poison() {
    let directory = private_tempdir().test_unwrap();
    let fixture = NamespaceFixture::new(&directory);
    let witness = fixture.witness(&directory);
    let pin = witness.pin().test_unwrap();
    drop(witness);
    let path = trusted_temp_path(&directory, "namespace-target-witness.sqlite");
    fixture.retain_foreign_archive(&path, "witness_gossip", "witness_conflicts");
    let reopened = SqliteKeyLogWitness::open(
        &path,
        fixture.a.policy.clone(),
        WitnessId::new("witness.a").test_unwrap(),
        Box::new(fixture.a.witnesses[0].clone()),
        Arc::new(FixedClock(5_000)),
    );
    assert!(
        reopened.is_ok(),
        "foreign archive prevented the local log from reopening"
    );
    let reopened = reopened.test_unwrap();
    assert_eq!(reopened.pin().test_unwrap(), pin);
    assert!(reopened.gossip_observations().test_unwrap().is_empty());
    assert!(reopened
        .service_gossip_observations()
        .test_unwrap()
        .iter()
        .all(|g| g.checkpoint.body.log_id == *fixture.a.policy.log_id()));
    assert!(reopened.conflicts().test_unwrap().is_empty());
    reopened
        .sign_candidate(
            &fixture.a_head,
            &fixture.a_store.synchronization_response(None).test_unwrap(),
        )
        .test_unwrap();
    fixture.assert_foreign_archive_preserved(&path, "witness_gossip", "witness_conflicts");
}

#[test]
fn review_namespace_verifier_rejects_foreign_gossip_before_retention() {
    let directory = private_tempdir().test_unwrap();
    let fixture = NamespaceFixture::new(&directory);
    let verifier = fixture.verifier(&directory);
    let pin = verifier.pin().test_unwrap();
    assert!(matches!(
        verifier.import_gossip(&fixture.b_gossip),
        Err(KeyringError::IdentityMismatch)
    ));
    assert!(verifier.gossip_observations().test_unwrap().is_empty());
    assert!(verifier.conflicts().test_unwrap().is_empty());
    assert_eq!(verifier.pin().test_unwrap(), pin);
}

#[test]
fn review_namespace_verifier_rejects_foreign_response_before_conflict() {
    let directory = private_tempdir().test_unwrap();
    let fixture = NamespaceFixture::new(&directory);
    let verifier = fixture.verifier(&directory);
    let pin = verifier.pin().test_unwrap();
    assert!(matches!(
        verifier.apply_sync(&fixture.b_response),
        Err(KeyringError::IdentityMismatch)
    ));
    assert!(verifier.conflicts().test_unwrap().is_empty());
    assert_eq!(verifier.pin().test_unwrap(), pin);
}

#[test]
fn review_namespace_verifier_reopens_with_foreign_archive_without_poison() {
    let directory = private_tempdir().test_unwrap();
    let fixture = NamespaceFixture::new(&directory);
    let verifier = fixture.verifier(&directory);
    let pin = verifier.pin().test_unwrap();
    drop(verifier);
    let path = trusted_temp_path(&directory, "namespace-target-verifier.sqlite");
    fixture.retain_foreign_archive(&path, "verifier_gossip", "verifier_conflicts");
    let reopened = SqlitePinnedKeyLogVerifier::open(
        &path,
        fixture.a.policy.clone(),
        Arc::new(FixedClock(5_000)),
    )
    .test_unwrap();
    assert_eq!(reopened.pin().test_unwrap(), pin);
    assert!(reopened.gossip_observations().test_unwrap().is_empty());
    assert!(reopened.conflicts().test_unwrap().is_empty());
    fixture.assert_foreign_archive_preserved(&path, "verifier_gossip", "verifier_conflicts");
}

#[test]
fn review_namespace_verifier_foreign_first_row_does_not_hide_local_fork() {
    let directory = private_tempdir().test_unwrap();
    let fixture = NamespaceFixture::new(&directory);
    let verifier = fixture.verifier(&directory);
    let pin = verifier.pin().test_unwrap();
    let local_fork = (1..=100)
        .map(|offset| {
            let mut body = fixture.a_head.body.clone();
            body.issued_at += offset;
            SignedKeyLogCheckpoint::sign(body, &fixture.a.operator).test_unwrap()
        })
        .max_by_key(|checkpoint| checkpoint.checkpoint_hash().test_unwrap().to_string())
        .test_unwrap();
    let foreign = (1..=100)
        .map(|offset| {
            let mut body = fixture.b_head.body.clone();
            body.issued_at += offset;
            SignedKeyLogCheckpoint::sign(body, &fixture.a.operator).test_unwrap()
        })
        .min_by_key(|checkpoint| checkpoint.checkpoint_hash().test_unwrap().to_string())
        .test_unwrap();
    assert!(
        foreign.checkpoint_hash().test_unwrap().to_string()
            < local_fork.checkpoint_hash().test_unwrap().to_string()
    );
    let path = trusted_temp_path(&directory, "namespace-target-verifier.sqlite");
    let connection = rusqlite::Connection::open(&path).test_unwrap();
    for checkpoint in [&foreign, &local_fork] {
        let gossip = CheckpointGossip {
            checkpoint: checkpoint.clone(),
            witness_signature: WitnessSignature::sign(
                checkpoint,
                WitnessId::new("witness.b").test_unwrap(),
                &fixture.a.witnesses[1],
            )
            .test_unwrap(),
        };
        connection.execute(
            "INSERT INTO verifier_gossip (checkpoint_hash, witness_id, checkpoint_sequence, tree_size, canonical_gossip) VALUES (?1, 'witness.b', 0, 1, ?2)",
            rusqlite::params![checkpoint.checkpoint_hash().test_unwrap().to_string(), chio_core_types::canonical_json_bytes(&gossip).test_unwrap()],
        ).test_unwrap();
    }
    drop(connection);
    let response = fixture.a_store.synchronization_response(None).test_unwrap();
    assert!(matches!(
        verifier.apply_sync(&response),
        Err(KeyringError::EquivocationDetected)
    ));
    let conflicts = verifier.conflicts().test_unwrap();
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].first.body.log_id, *fixture.a.policy.log_id());
    assert_eq!(
        conflicts[0].conflicting.body.log_id,
        *fixture.a.policy.log_id()
    );
    let evidence_pair = std::collections::BTreeSet::from([
        conflicts[0]
            .first
            .checkpoint_hash()
            .test_unwrap()
            .to_string(),
        conflicts[0]
            .conflicting
            .checkpoint_hash()
            .test_unwrap()
            .to_string(),
    ]);
    assert_eq!(
        evidence_pair,
        std::collections::BTreeSet::from([
            fixture.a_head.checkpoint_hash().test_unwrap().to_string(),
            local_fork.checkpoint_hash().test_unwrap().to_string(),
        ])
    );
    assert_eq!(verifier.pin().test_unwrap(), pin);
    let connection = rusqlite::Connection::open(&path).test_unwrap();
    let retained: i64 = connection
        .query_row("SELECT COUNT(*) FROM verifier_gossip", [], |row| row.get(0))
        .test_unwrap();
    assert_eq!(retained, 2);
}

#[test]
fn review_namespace_verifier_reopen_refuses_retained_local_fork() {
    let directory = private_tempdir().test_unwrap();
    let fixture = NamespaceFixture::new(&directory);
    let verifier = fixture.verifier(&directory);
    drop(verifier);
    let path = trusted_temp_path(&directory, "namespace-target-verifier.sqlite");
    let mut body = fixture.a_head.body.clone();
    body.issued_at += 1;
    let fork = SignedKeyLogCheckpoint::sign(body, &fixture.a.operator).test_unwrap();
    let gossip = CheckpointGossip {
        witness_signature: WitnessSignature::sign(
            &fork,
            WitnessId::new("witness.b").test_unwrap(),
            &fixture.a.witnesses[1],
        )
        .test_unwrap(),
        checkpoint: fork,
    };
    let connection = rusqlite::Connection::open(&path).test_unwrap();
    connection.execute(
        "INSERT INTO verifier_gossip (checkpoint_hash, witness_id, checkpoint_sequence, tree_size, canonical_gossip) VALUES (?1, 'witness.b', 0, 1, ?2)",
        rusqlite::params![gossip.checkpoint.checkpoint_hash().test_unwrap().to_string(), chio_core_types::canonical_json_bytes(&gossip).test_unwrap()],
    ).test_unwrap();
    drop(connection);
    let reopened = SqlitePinnedKeyLogVerifier::open(
        &path,
        fixture.a.policy.clone(),
        Arc::new(FixedClock(5_000)),
    );
    assert!(
        matches!(reopened, Err(KeyringError::EquivocationDetected)),
        "retained local split view was ignored at startup"
    );
    let connection = rusqlite::Connection::open(&path).test_unwrap();
    let retained: i64 = connection
        .query_row("SELECT COUNT(*) FROM verifier_gossip", [], |row| row.get(0))
        .test_unwrap();
    assert_eq!(retained, 1);
}

fn observed_pin(checkpoint_sequence: u64) -> chio_keyring::KeyLogPin {
    chio_keyring::KeyLogPin {
        checkpoint_sequence,
        tree_size: checkpoint_sequence.checked_add(1).test_unwrap(),
        checkpoint_hash: chio_core_types::sha256(&checkpoint_sequence.to_be_bytes()),
        root_hash: chio_core_types::sha256(b"observed-root"),
        signing_epoch: 0,
    }
}

fn audit_store(fixture: &Fixture, path: &Path) -> SqlitePinnedKeyLogVerifier {
    if path.exists() {
        SqlitePinnedKeyLogVerifier::open(path, fixture.policy.clone(), Arc::new(FixedClock(5_000)))
            .test_unwrap()
    } else {
        SqlitePinnedKeyLogVerifier::provision(
            path,
            fixture.policy.clone(),
            Arc::new(FixedClock(5_000)),
        )
        .test_unwrap()
    }
}

#[test]
fn an_auditor_pins_each_witness_storage_identity_across_its_restart() {
    let fixture = Fixture::new();
    let directory = private_tempdir().test_unwrap();
    let path = trusted_temp_path(&directory, "audit.sqlite");
    let witness = WitnessId::new("witness.a").test_unwrap();
    let original = chio_core_types::sha256(b"witness.a.original-store");
    let replacement = chio_core_types::sha256(b"witness.a.replacement-store");
    {
        let auditor = audit_store(&fixture, &path);
        auditor
            .pin_witness_observation(&witness, original, None)
            .test_unwrap();
        auditor
            .pin_witness_observation(&witness, original, Some(&observed_pin(0)))
            .test_unwrap();
        assert!(matches!(
            auditor.pin_witness_observation(&witness, replacement, Some(&observed_pin(0))),
            Err(KeyringError::WitnessIdentityChanged)
        ));
    }

    let restarted = audit_store(&fixture, &path);
    restarted
        .pin_witness_observation(&witness, original, Some(&observed_pin(1)))
        .test_unwrap();
    assert!(matches!(
        restarted.pin_witness_observation(&witness, replacement, Some(&observed_pin(1))),
        Err(KeyringError::WitnessIdentityChanged)
    ));
    restarted
        .pin_witness_observation(
            &WitnessId::new("witness.b").test_unwrap(),
            replacement,
            None,
        )
        .test_unwrap();
}

#[test]
fn an_auditor_refuses_a_witness_whose_pin_falls_behind_what_it_observed() {
    let fixture = Fixture::new();
    let directory = private_tempdir().test_unwrap();
    let path = trusted_temp_path(&directory, "audit.sqlite");
    let witness = WitnessId::new("witness.a").test_unwrap();
    let identity = chio_core_types::sha256(b"witness.a.store");
    {
        let auditor = audit_store(&fixture, &path);
        auditor
            .pin_witness_observation(&witness, identity, Some(&observed_pin(2)))
            .test_unwrap();
        assert!(matches!(
            auditor.pin_witness_observation(&witness, identity, Some(&observed_pin(1))),
            Err(KeyringError::WitnessIdentityChanged)
        ));
    }

    let restarted = audit_store(&fixture, &path);
    assert!(matches!(
        restarted.pin_witness_observation(&witness, identity, None),
        Err(KeyringError::WitnessIdentityChanged)
    ));
    restarted
        .pin_witness_observation(&witness, identity, Some(&observed_pin(2)))
        .test_unwrap();
    restarted
        .pin_witness_observation(&witness, identity, Some(&observed_pin(3)))
        .test_unwrap();
}

#[test]
fn an_auditor_refuses_to_pin_a_witness_outside_its_policy() {
    let fixture = Fixture::new();
    let directory = private_tempdir().test_unwrap();
    let auditor = audit_store(&fixture, &trusted_temp_path(&directory, "audit.sqlite"));
    assert!(matches!(
        auditor.pin_witness_observation(
            &WitnessId::new("witness.unknown").test_unwrap(),
            chio_core_types::sha256(b"unknown-store"),
            None,
        ),
        Err(KeyringError::InvalidSignature)
    ));
}
