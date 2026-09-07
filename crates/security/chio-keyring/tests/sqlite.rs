use chio_test_support::prelude::*;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};

use chio_core_types::{
    Ed25519Backend, Keypair, PublicKey, Result as CoreResult, Signature, SigningAlgorithm,
    SigningBackend,
};
use chio_keyring::{
    derive_key_id, durable_storage_identity, AnchorId, AuthorityId, BootstrapAuthorization,
    CheckpointStage, EventId, EventReason, KeyLogAuthorizations, KeyLogEventBody, KeyLogOperation,
    KeyLogPolicy, KeyLogPolicyConfig, LogId, NewKeyProofOfPossession, OldKeyAuthorization,
    RecoveryPolicyId, SignedKeyLogEvent, SigningTopology, SqliteKeyLogStore, WitnessId,
    WitnessRosterId, WitnessSignature, KEY_LOG_EVENT_SCHEMA,
};

mod support;

use support::{private_tempdir, trusted_temp_path};

fn backend(seed: u8) -> Ed25519Backend {
    Ed25519Backend::new(Keypair::from_seed(&[seed; 32]))
}

struct Fixture {
    bootstrap: Ed25519Backend,
    operator: Ed25519Backend,
    old: Ed25519Backend,
    witness_a: Ed25519Backend,
    witness_b: Ed25519Backend,
    witness_c: Ed25519Backend,
}

struct FixedClock(u64);

impl chio_keyring::TrustedClock for FixedClock {
    fn now(&self) -> chio_keyring::Result<u64> {
        Ok(self.0)
    }
}

struct MutableClock(AtomicU64);

impl MutableClock {
    fn set(&self, now: u64) {
        self.0.store(now, Ordering::SeqCst);
    }
}

impl chio_keyring::TrustedClock for MutableClock {
    fn now(&self) -> chio_keyring::Result<u64> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

impl Fixture {
    fn new() -> Self {
        Self {
            bootstrap: backend(1),
            operator: backend(10),
            old: backend(2),
            witness_a: backend(20),
            witness_b: backend(21),
            witness_c: backend(22),
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
            recovery_keys: BTreeMap::new(),
            recovery_threshold: 0,
            max_checkpoint_future_skew: 100,
        })
        .test_unwrap()
    }

    fn policy(&self) -> KeyLogPolicy {
        self.policy_without_auditors()
            .with_auditor_roots(BTreeMap::from([
                ("audit.a".to_string(), backend(80).public_key()),
                ("audit.b".to_string(), backend(81).public_key()),
            ]))
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

    fn rotation(
        &self,
        genesis: &SignedKeyLogEvent,
        new: &Ed25519Backend,
        event_id: &str,
    ) -> SignedKeyLogEvent {
        let body = KeyLogEventBody {
            schema: KEY_LOG_EVENT_SCHEMA.to_string(),
            log_id: genesis.body.log_id.clone(),
            sequence: 1,
            event_id: EventId::new(event_id).test_unwrap(),
            previous_event_hash: Some(genesis.envelope_hash().test_unwrap()),
            authority_id: genesis.body.authority_id.clone(),
            key_id: derive_key_id(new.algorithm(), &new.public_key()).test_unwrap(),
            algorithm: new.algorithm(),
            public_key: new.public_key(),
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
                NewKeyProofOfPossession::sign(&body, new).test_unwrap(),
            ),
            body,
        }
    }
}

#[test]
fn durable_store_rejects_changed_security_configuration() {
    let directory = private_tempdir().test_unwrap();
    let path = trusted_temp_path(&directory, "policy-bound.sqlite");
    let fixture = Fixture::new();
    let policy = fixture.policy();
    drop(SqliteKeyLogStore::open(&path, policy.clone()).test_unwrap());
    drop(SqliteKeyLogStore::open(&path, policy).test_unwrap());

    let changed_policy = KeyLogPolicy::new(KeyLogPolicyConfig {
        log_id: LogId::new("log.enterprise.test").test_unwrap(),
        authority_id: AuthorityId::new("authority.enterprise.test").test_unwrap(),
        bootstrap_key: fixture.bootstrap.public_key(),
        operator_key: fixture.operator.public_key(),
        witness_roster_id: WitnessRosterId::new("roster.enterprise.v1").test_unwrap(),
        witness_keys: BTreeMap::from([
            (
                WitnessId::new("witness.a").test_unwrap(),
                backend(90).public_key(),
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
        recovery_keys: BTreeMap::new(),
        recovery_threshold: 0,
        max_checkpoint_future_skew: 100,
    })
    .test_unwrap();
    assert!(SqliteKeyLogStore::open(&path, changed_policy).is_err());

    let changed_artifact_time_policy = fixture
        .policy()
        .with_artifact_time_roots(BTreeMap::from([(
            AnchorId::new("timestamp.enterprise.v1").test_unwrap(),
            backend(91).public_key(),
        )]))
        .test_unwrap();
    assert!(SqliteKeyLogStore::open(&path, changed_artifact_time_policy).is_err());

    let changed_auditor_policy = fixture
        .policy_without_auditors()
        .with_auditor_roots(BTreeMap::from([
            ("audit.a".to_string(), backend(80).public_key()),
            ("audit.b".to_string(), backend(82).public_key()),
        ]))
        .test_unwrap();
    assert!(SqliteKeyLogStore::open(&path, changed_auditor_policy).is_err());

    let changed_skew_policy = KeyLogPolicy::new(KeyLogPolicyConfig {
        log_id: LogId::new("log.enterprise.test").test_unwrap(),
        authority_id: AuthorityId::new("authority.enterprise.test").test_unwrap(),
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
        recovery_keys: BTreeMap::new(),
        recovery_threshold: 0,
        max_checkpoint_future_skew: 101,
    })
    .test_unwrap();
    assert!(SqliteKeyLogStore::open(&path, changed_skew_policy).is_err());
}

#[test]
fn append_checkpoint_witness_activation_and_reopen_are_transactional() {
    let directory = private_tempdir().test_unwrap();
    let path = trusted_temp_path(&directory, "keylog.sqlite");
    let fixture = Fixture::new();
    let policy = fixture.policy();
    let genesis = fixture.genesis();
    let new = backend(3);
    let rotation = fixture.rotation(&genesis, &new, "event.rotation.1");

    {
        let store = SqliteKeyLogStore::open_with_clock(
            &path,
            policy.clone(),
            SigningTopology::LocalSingleWriter,
            Arc::new(FixedClock(3_010)),
        )
        .test_unwrap();
        let genesis_checkpoint = store
            .append_event(&genesis, &fixture.operator)
            .test_unwrap();
        assert_eq!(genesis_checkpoint.body.tree_size, 1);
        let rotation_checkpoint = store
            .append_event(&rotation, &fixture.operator)
            .test_unwrap();
        assert_eq!(
            store
                .load_state()
                .test_unwrap()
                .test_unwrap()
                .active_signing_key()
                .test_unwrap()
                .key_id,
            genesis.body.key_id
        );
        assert_eq!(
            store.load_events().test_unwrap(),
            vec![genesis.clone(), rotation.clone()]
        );

        let checkpoint_hash = rotation_checkpoint.checkpoint_hash().test_unwrap();
        let first = WitnessSignature::sign(
            &rotation_checkpoint,
            WitnessId::new("witness.a").test_unwrap(),
            &fixture.witness_a,
        )
        .test_unwrap();
        let second = WitnessSignature::sign(
            &rotation_checkpoint,
            WitnessId::new("witness.b").test_unwrap(),
            &fixture.witness_b,
        )
        .test_unwrap();
        assert_eq!(
            store
                .store_witness_signature(&checkpoint_hash, &first)
                .test_unwrap()
                .stage,
            CheckpointStage::Pending
        );
        let updated = rusqlite::Connection::open(&path)
            .test_unwrap()
            .execute(
                "UPDATE key_checkpoints SET stage = 'witnessed' WHERE checkpoint_hash = ?1",
                [checkpoint_hash.to_string()],
            )
            .test_unwrap();
        assert_eq!(updated, 1);
        assert!(store
            .activate_rotation(&rotation.body.event_id, &checkpoint_hash, &fixture.operator)
            .is_err());
        let pending = store.load_state().test_unwrap().test_unwrap();
        assert_eq!(
            pending.active_signing_key().test_unwrap().key_id,
            genesis.body.key_id
        );
        assert_eq!(
            pending.pending_rotation_key().test_unwrap().key_id,
            rotation.body.key_id
        );
        assert_eq!(
            store
                .store_witness_signature(&checkpoint_hash, &second)
                .test_unwrap()
                .stage,
            CheckpointStage::Witnessed
        );

        let activated = store
            .activate_rotation(&rotation.body.event_id, &checkpoint_hash, &fixture.operator)
            .test_unwrap();
        assert_eq!(
            activated.active_signing_key().test_unwrap().key_id,
            rotation.body.key_id
        );
        assert_eq!(activated.signing_epoch(), 1);
        assert_eq!(
            activated.active_signing_key().test_unwrap().activated_at,
            3_010
        );
        assert_eq!(
            store
                .activate_rotation(&rotation.body.event_id, &checkpoint_hash, &fixture.operator,)
                .test_unwrap(),
            activated,
        );
        assert_eq!(store.head().test_unwrap().test_unwrap().tree_size, 2);
        assert_eq!(store.load_checkpoints().test_unwrap().len(), 2);
    }

    let reopened = SqliteKeyLogStore::open(&path, policy).test_unwrap();
    assert_eq!(reopened.load_events().test_unwrap().len(), 2);
    assert_eq!(
        reopened
            .load_state()
            .test_unwrap()
            .test_unwrap()
            .active_signing_key()
            .test_unwrap()
            .key_id,
        rotation.body.key_id
    );
    assert_eq!(reopened.head().test_unwrap().test_unwrap().signing_epoch, 1);
}

#[test]
fn append_retry_returns_existing_checkpoint_and_conflict_does_not_mutate_log() {
    let directory = private_tempdir().test_unwrap();
    let path = trusted_temp_path(&directory, "append-retry.sqlite");
    let fixture = Fixture::new();
    let policy = fixture.policy();
    let genesis = fixture.genesis();
    let store = SqliteKeyLogStore::open(&path, policy).test_unwrap();

    let first = store
        .append_event(&genesis, &fixture.operator)
        .test_unwrap();
    let retry = store
        .append_event(&genesis, &fixture.operator)
        .test_unwrap();
    assert_eq!(retry, first);
    assert_eq!(store.load_events().test_unwrap().len(), 1);
    assert_eq!(store.load_checkpoints().test_unwrap().len(), 1);

    let mut conflict = genesis;
    conflict.body.event_id = EventId::new("event.conflict").test_unwrap();
    assert!(store.append_event(&conflict, &fixture.operator).is_err());
    assert_eq!(store.load_events().test_unwrap().len(), 1);
    assert_eq!(store.load_checkpoints().test_unwrap().len(), 1);
}

#[test]
fn write_and_signing_failures_leave_no_partial_event_checkpoint_or_state() {
    let directory = private_tempdir().test_unwrap();
    let valid_path = trusted_temp_path(&directory, "valid-keylog.sqlite");
    let path = trusted_temp_path(&directory, "keylog.sqlite");
    let fixture = Fixture::new();
    let policy = fixture.policy();
    let genesis = fixture.genesis();
    let valid_store = SqliteKeyLogStore::open(&valid_path, policy.clone()).test_unwrap();
    valid_store
        .append_event(&genesis, &fixture.operator)
        .test_unwrap();
    assert_eq!(valid_store.load_events().test_unwrap().len(), 1);
    assert_eq!(valid_store.load_checkpoints().test_unwrap().len(), 1);
    assert!(valid_store.head().test_unwrap().is_some());
    drop(valid_store);

    let store = SqliteKeyLogStore::open(&path, policy.clone()).test_unwrap();

    rusqlite::Connection::open(&path)
        .test_unwrap()
        .execute_batch(
            "CREATE TRIGGER fail_key_state BEFORE INSERT ON key_state BEGIN SELECT RAISE(ABORT, 'injected'); END;",
        )
        .test_unwrap();
    assert!(store.append_event(&genesis, &fixture.operator).is_err());
    assert!(store.load_events().test_unwrap().is_empty());
    assert!(store.load_checkpoints().test_unwrap().is_empty());
    assert!(store.head().test_unwrap().is_none());
    drop(store);

    rusqlite::Connection::open(&path)
        .test_unwrap()
        .execute_batch("DROP TRIGGER fail_key_state;")
        .test_unwrap();
    let store = SqliteKeyLogStore::open(&path, policy).test_unwrap();
    let failing = FailingBackend {
        public: fixture.operator.public_key(),
    };
    assert!(store.append_event(&genesis, &failing).is_err());
    assert!(store.load_events().test_unwrap().is_empty());
    assert!(store.load_checkpoints().test_unwrap().is_empty());
}

#[test]
fn concurrent_rotation_proposals_commit_exactly_one_head() {
    let directory = private_tempdir().test_unwrap();
    let path = trusted_temp_path(&directory, "keylog.sqlite");
    let fixture = Fixture::new();
    let policy = fixture.policy();
    let genesis = fixture.genesis();
    let store = Arc::new(SqliteKeyLogStore::open(&path, policy.clone()).test_unwrap());
    store
        .append_event(&genesis, &fixture.operator)
        .test_unwrap();
    let first = fixture.rotation(&genesis, &backend(3), "event.rotation.a");
    let second = fixture.rotation(&genesis, &backend(4), "event.rotation.b");
    let barrier = Arc::new(Barrier::new(2));
    let mut threads = Vec::new();
    for event in [first, second] {
        let store = Arc::clone(&store);
        let operator = fixture.operator.clone();
        let barrier = Arc::clone(&barrier);
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            store.append_event(&event, &operator).is_ok()
        }));
    }
    let successes = threads
        .into_iter()
        .map(|thread| usize::from(thread.join().test_unwrap()))
        .sum::<usize>();
    assert_eq!(successes, 1);
    let observer = SqliteKeyLogStore::open_observer(&path, policy).test_unwrap();
    assert_eq!(observer.load_events().test_unwrap().len(), 2);
}

#[test]
fn startup_rebuild_rejects_root_corruption_and_multi_worker_topology() {
    let directory = private_tempdir().test_unwrap();
    let path = trusted_temp_path(&directory, "keylog.sqlite");
    let fixture = Fixture::new();
    let policy = fixture.policy();
    let genesis = fixture.genesis();
    {
        let store = SqliteKeyLogStore::open(&path, policy.clone()).test_unwrap();
        store
            .append_event(&genesis, &fixture.operator)
            .test_unwrap();
    }
    rusqlite::Connection::open(&path)
        .test_unwrap()
        .execute("UPDATE key_state SET root_hash = '00'", [])
        .test_unwrap();
    assert!(SqliteKeyLogStore::open(&path, policy.clone()).is_err());

    let other = trusted_temp_path(&directory, "multi.sqlite");
    assert!(
        SqliteKeyLogStore::open_with_topology(other, policy, SigningTopology::MultiWorker,)
            .is_err()
    );
}

#[test]
fn local_single_writer_is_fenced_across_store_handles_while_observers_remain_available() {
    let directory = private_tempdir().test_unwrap();
    let path = trusted_temp_path(&directory, "single-writer.sqlite");
    let fixture = Fixture::new();
    let policy = fixture.policy();
    let writer = SqliteKeyLogStore::open(&path, policy.clone()).test_unwrap();
    assert!(SqliteKeyLogStore::open_existing(&path, policy.clone()).is_err());
    let observer = SqliteKeyLogStore::open_observer(&path, policy.clone()).test_unwrap();
    assert!(observer.load_state().test_unwrap().is_none());
    drop(observer);
    drop(writer);
    SqliteKeyLogStore::open_existing(&path, policy).test_unwrap();
}

#[test]
fn activation_rejects_clock_rollback_and_preserves_pending_selector() {
    let directory = private_tempdir().test_unwrap();
    let path = trusted_temp_path(&directory, "clock-rollback.sqlite");
    let fixture = Fixture::new();
    let policy = fixture.policy();
    let clock = Arc::new(MutableClock(AtomicU64::new(3_000)));
    let store = SqliteKeyLogStore::open_with_clock(
        &path,
        policy,
        SigningTopology::LocalSingleWriter,
        clock.clone(),
    )
    .test_unwrap();
    let genesis = fixture.genesis();
    let rotation = fixture.rotation(&genesis, &backend(3), "event.rotation.rollback");
    store
        .append_event(&genesis, &fixture.operator)
        .test_unwrap();
    let checkpoint = store
        .append_event(&rotation, &fixture.operator)
        .test_unwrap();
    let checkpoint_hash = checkpoint.checkpoint_hash().test_unwrap();
    for (id, witness) in [
        ("witness.a", &fixture.witness_a),
        ("witness.b", &fixture.witness_b),
    ] {
        store
            .store_witness_signature(
                &checkpoint_hash,
                &WitnessSignature::sign(&checkpoint, WitnessId::new(id).test_unwrap(), witness)
                    .test_unwrap(),
            )
            .test_unwrap();
    }
    clock.set(2_999);
    assert!(store
        .activate_rotation(&rotation.body.event_id, &checkpoint_hash, &fixture.operator,)
        .is_err());
    let state = store.load_state().test_unwrap().test_unwrap();
    assert_eq!(
        state.active_signing_key().test_unwrap().key_id,
        genesis.body.key_id
    );
    assert_eq!(
        state.pending_rotation_key().test_unwrap().key_id,
        rotation.body.key_id
    );
}

#[test]
fn oversized_sqlite_blob_is_refused_before_blob_materialization() {
    let directory = private_tempdir().test_unwrap();
    let path = trusted_temp_path(&directory, "oversized.sqlite");
    let fixture = Fixture::new();
    let store = SqliteKeyLogStore::open(&path, fixture.policy()).test_unwrap();
    store
        .append_event(&fixture.genesis(), &fixture.operator)
        .test_unwrap();
    rusqlite::Connection::open(&path)
        .test_unwrap()
        .execute_batch(
            "PRAGMA ignore_check_constraints = ON; UPDATE key_events SET canonical_envelope = zeroblob(1048577) WHERE sequence = 0;",
        )
        .test_unwrap();
    assert!(store.load_events().is_err());
}

#[test]
fn key_log_rejects_ephemeral_sqlite_paths() {
    let fixture = Fixture::new();
    assert!(SqliteKeyLogStore::open(":memory:", fixture.policy()).is_err());
    assert!(SqliteKeyLogStore::open("file::memory:?cache=shared", fixture.policy()).is_err());
    assert!(
        SqliteKeyLogStore::open("file:keylog?mode=memory&cache=shared", fixture.policy()).is_err()
    );
}

#[cfg(unix)]
#[test]
fn key_log_storage_identity_is_retained_across_path_replacement() {
    use std::os::unix::fs::OpenOptionsExt;

    let directory = private_tempdir().test_unwrap();
    let path = trusted_temp_path(&directory, "operator.sqlite");
    let displaced = trusted_temp_path(&directory, "operator-original.sqlite");
    let store = SqliteKeyLogStore::open(&path, Fixture::new().policy()).test_unwrap();
    let opened_identity = store.storage_identity();

    std::fs::rename(&path, &displaced).test_unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .test_unwrap();

    assert_eq!(store.storage_identity(), opened_identity);
    assert_ne!(
        durable_storage_identity(&path).test_unwrap(),
        opened_identity
    );
}

#[cfg(unix)]
#[test]
fn key_log_store_rejects_hard_link_database_aliases() {
    let directory = private_tempdir().test_unwrap();
    let path = trusted_temp_path(&directory, "operator.sqlite");
    let alias = trusted_temp_path(&directory, "operator-alias.sqlite");
    let store = SqliteKeyLogStore::open(&path, Fixture::new().policy()).test_unwrap();
    let opened_identity = store.storage_identity();
    std::fs::hard_link(&path, &alias).test_unwrap();

    assert!(durable_storage_identity(&path).is_err());
    assert!(durable_storage_identity(&alias).is_err());
    assert_eq!(store.storage_identity(), opened_identity);
}

#[cfg(unix)]
#[test]
fn key_log_store_rejects_untrusted_parent_directory_swap_boundary() {
    use std::os::unix::fs::PermissionsExt;

    let directory = private_tempdir().test_unwrap();
    let untrusted_parent = trusted_temp_path(&directory, "untrusted-parent");
    std::fs::create_dir(&untrusted_parent).test_unwrap();
    std::fs::set_permissions(&untrusted_parent, std::fs::Permissions::from_mode(0o777))
        .test_unwrap();
    let path = untrusted_parent.join("operator.sqlite");

    let error = match SqliteKeyLogStore::open(&path, Fixture::new().policy()) {
        Ok(_) => panic!("untrusted parent directory must fail closed"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("owned by the service or root and grant no untrusted write access"));
    assert!(!path.exists());
}

struct FailingBackend {
    public: PublicKey,
}

impl SigningBackend for FailingBackend {
    fn algorithm(&self) -> SigningAlgorithm {
        self.public.algorithm()
    }

    fn public_key(&self) -> PublicKey {
        self.public.clone()
    }

    fn sign_bytes(&self, _message: &[u8]) -> CoreResult<Signature> {
        Err(chio_core_types::Error::InvalidSignature(
            "injected signing failure".to_string(),
        ))
    }
}
