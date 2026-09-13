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
    SqliteKeyLogStore, SqliteKeyLogWitness, SqlitePinnedKeyLogVerifier, TrustedClock, WitnessId,
    WitnessRosterId, WitnessSignature, KEY_LOG_EVENT_SCHEMA, MAX_SYNC_ITEMS,
};

mod support;

use support::{private_tempdir, trusted_temp_path};

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
    witnesses: [Ed25519Backend; 3],
    policy: KeyLogPolicy,
}

impl Fixture {
    fn new() -> Self {
        let bootstrap = backend(1);
        let operator = backend(10);
        let old = backend(2);
        let new = backend(3);
        let witnesses = [backend(20), backend(21), backend(22)];
        let policy = KeyLogPolicy::new(KeyLogPolicyConfig {
            log_id: LogId::new("log.witness.test").test_unwrap(),
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
