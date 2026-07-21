use chio_test_support::prelude::*;

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chio_core_types::{
    Ed25519Backend, Keypair, PublicKey, Signature, SigningAlgorithm, SigningBackend,
};
use chio_keyring::{
    derive_key_id, AnchorId, ArtifactTimeAnchorKind, AuthorityId, BootstrapAuthorization, EventId,
    EventReason, KeyLogAuthorizations, KeyLogEventBody, KeyLogOperation, KeyLogPolicy,
    KeyLogPolicyConfig, KeyringSigningRouter, LogId, NewKeyProofOfPossession, OldKeyAuthorization,
    RecoveryPolicyId, SignedArtifactTimeAnchor, SignedKeyLogEvent, SigningTopology,
    SqliteKeyLogStore, SqlitePinnedKeyLogVerifier, TrustedClock, WitnessId, WitnessRosterId,
    WitnessSignature, WitnessedRotationRuntime, KEY_LOG_EVENT_SCHEMA,
};

mod support;

use support::trusted_temp_path;

fn backend(seed: u8) -> Ed25519Backend {
    Ed25519Backend::new(Keypair::from_seed(&[seed; 32]))
}

struct FixedClock(u64);

impl TrustedClock for FixedClock {
    fn now(&self) -> chio_keyring::Result<u64> {
        Ok(self.0)
    }
}

struct AcceptingEnterpriseReceiptSink;

impl chio_keyring::KeyEnterpriseReceiptSink for AcceptingEnterpriseReceiptSink {
    fn persist(
        &self,
        _receipt: &chio_keyring::SignedKeyEnterpriseReceipt,
    ) -> chio_keyring::Result<()> {
        Ok(())
    }
}

struct AcceptingActivationGuard;

impl chio_keyring::KeyLogActivationGuard for AcceptingActivationGuard {
    fn require_activation(&self) -> chio_keyring::Result<()> {
        Ok(())
    }
}

struct ReadyLog {
    store: Arc<SqliteKeyLogStore>,
    operator: Ed25519Backend,
    old: Ed25519Backend,
    new: Ed25519Backend,
    artifact_time_signer: Ed25519Backend,
    artifact_time_anchor_id: AnchorId,
    rotation: SignedKeyLogEvent,
    checkpoint_hash: chio_core_types::Hash,
    policy: KeyLogPolicy,
}

fn ready_log(path: &Path) -> ReadyLog {
    let bootstrap = backend(1);
    let operator = backend(10);
    let old = backend(2);
    let new = backend(3);
    let witness_a = backend(20);
    let witness_b = backend(21);
    let witness_c = backend(22);
    let artifact_time_signer = backend(70);
    let artifact_time_anchor_id = AnchorId::new("timestamp.router.v1").test_unwrap();
    let log_id = LogId::new("log.router.test").test_unwrap();
    let authority_id = AuthorityId::new("authority.router.test").test_unwrap();
    let roster_id = WitnessRosterId::new("roster.router.v1").test_unwrap();
    let policy = KeyLogPolicy::new(KeyLogPolicyConfig {
        log_id: log_id.clone(),
        authority_id: authority_id.clone(),
        bootstrap_key: bootstrap.public_key(),
        operator_key: operator.public_key(),
        witness_roster_id: roster_id.clone(),
        witness_keys: BTreeMap::from([
            (
                WitnessId::new("witness.a").test_unwrap(),
                witness_a.public_key(),
            ),
            (
                WitnessId::new("witness.b").test_unwrap(),
                witness_b.public_key(),
            ),
            (
                WitnessId::new("witness.c").test_unwrap(),
                witness_c.public_key(),
            ),
        ]),
        recovery_policy_id: RecoveryPolicyId::new("recovery.router.v1").test_unwrap(),
        recovery_keys: BTreeMap::new(),
        recovery_threshold: 0,
        max_checkpoint_future_skew: 100,
    })
    .test_unwrap()
    .with_artifact_time_roots(BTreeMap::from([(
        artifact_time_anchor_id.clone(),
        artifact_time_signer.public_key(),
    )]))
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
        log_id,
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
        effective_at: 2_000,
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
    let store = Arc::new(
        SqliteKeyLogStore::open_with_clock(
            path,
            policy.clone(),
            SigningTopology::LocalSingleWriter,
            Arc::new(FixedClock(3_010)),
        )
        .test_unwrap(),
    );
    let genesis_checkpoint = store.append_event(&genesis, &operator).test_unwrap();
    let checkpoint = store.append_event(&rotation, &operator).test_unwrap();
    let checkpoint_hash = checkpoint.checkpoint_hash().test_unwrap();
    for witnessed_checkpoint in [&genesis_checkpoint, &checkpoint] {
        let witnessed_checkpoint_hash = witnessed_checkpoint.checkpoint_hash().test_unwrap();
        for (id, witness) in [("witness.a", &witness_a), ("witness.b", &witness_b)] {
            let signature = WitnessSignature::sign(
                witnessed_checkpoint,
                WitnessId::new(id).test_unwrap(),
                witness,
            )
            .test_unwrap();
            store
                .store_witness_signature(&witnessed_checkpoint_hash, &signature)
                .test_unwrap();
        }
    }
    ReadyLog {
        store,
        operator,
        old,
        new,
        artifact_time_signer,
        artifact_time_anchor_id,
        rotation,
        checkpoint_hash,
        policy,
    }
}

#[test]
fn router_persists_epoch_evidence_cuts_over_atomically_and_reopens_exact_selector() {
    let directory = tempfile::tempdir().test_unwrap();
    let path = trusted_temp_path(&directory, "router.sqlite");
    let ready = ready_log(&path);
    let router = KeyringSigningRouter::open(Arc::clone(&ready.store), Box::new(ready.old.clone()))
        .test_unwrap();
    let mut staged = router
        .stage_pending(
            ready.rotation.body.event_id.clone(),
            Box::new(ready.new.clone()),
        )
        .test_unwrap();
    assert!(router
        .stage_pending(
            ready.rotation.body.event_id.clone(),
            Box::new(ready.new.clone()),
        )
        .is_err());

    let first = router
        .sign_canonical(0, &serde_json::json!({"artifact": 1}))
        .test_unwrap();
    let first_retry = router
        .sign_canonical(0, &serde_json::json!({"artifact": 1}))
        .test_unwrap();
    assert_eq!(first_retry, first);
    assert_eq!(first.signing_epoch, 0);
    assert_eq!(
        first.key_id,
        derive_key_id(ready.old.algorithm(), &ready.old.public_key()).test_unwrap()
    );
    let mut corrupted_evidence = first.clone();
    corrupted_evidence.artifact_signature =
        ready.old.sign_bytes(b"corrupted evidence").test_unwrap();
    assert!(corrupted_evidence.verify(&ready.old.public_key()).is_err());
    assert!(router
        .sign_canonical(1, &serde_json::json!({"artifact": 2}))
        .is_err());

    router
        .activate_rotation(&mut staged, &ready.checkpoint_hash, &ready.operator)
        .test_unwrap();
    router
        .activate_rotation(&mut staged, &ready.checkpoint_hash, &ready.operator)
        .test_unwrap();
    assert!(router
        .sign_canonical(0, &serde_json::json!({"artifact": 3}))
        .is_err());
    let second = router
        .sign_canonical(1, &serde_json::json!({"artifact": 4}))
        .test_unwrap();
    assert_eq!(second.signing_epoch, 1);
    assert_eq!(
        second.key_id,
        derive_key_id(ready.new.algorithm(), &ready.new.public_key()).test_unwrap()
    );
    assert_eq!(
        ready.store.load_artifact_signatures().test_unwrap().len(),
        2
    );
    drop(router);
    drop(ready.store);

    let reopened_store = Arc::new(SqliteKeyLogStore::open(&path, ready.policy).test_unwrap());
    assert!(KeyringSigningRouter::open(Arc::clone(&reopened_store), Box::new(ready.old)).is_err());
    KeyringSigningRouter::open(reopened_store, Box::new(ready.new)).test_unwrap();
}

#[test]
fn concurrent_duplicate_signing_returns_one_durable_artifact() {
    let directory = tempfile::tempdir().test_unwrap();
    let ready = ready_log(&trusted_temp_path(&directory, "duplicate.sqlite"));
    let router = Arc::new(
        KeyringSigningRouter::open(Arc::clone(&ready.store), Box::new(ready.old.clone()))
            .test_unwrap(),
    );
    let barrier = Arc::new(std::sync::Barrier::new(16));
    let handles = (0..16)
        .map(|_| {
            let router = Arc::clone(&router);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                router.sign_bytes(0, b"duplicate artifact").test_unwrap()
            })
        })
        .collect::<Vec<_>>();
    let evidence = handles
        .into_iter()
        .map(|handle| handle.join().test_unwrap())
        .collect::<Vec<_>>();
    assert!(evidence.windows(2).all(|pair| pair[0] == pair[1]));
    assert_eq!(
        ready.store.load_artifact_signatures().test_unwrap().len(),
        1
    );
}

struct BlockingBackend {
    inner: Ed25519Backend,
    started: SyncSender<()>,
    release: Mutex<Receiver<()>>,
    blocked_once: AtomicBool,
}

impl SigningBackend for BlockingBackend {
    fn algorithm(&self) -> SigningAlgorithm {
        self.inner.algorithm()
    }

    fn public_key(&self) -> PublicKey {
        self.inner.public_key()
    }

    fn sign_bytes(&self, message: &[u8]) -> chio_core_types::Result<Signature> {
        if self.blocked_once.swap(true, Ordering::SeqCst) {
            return self.inner.sign_bytes(message);
        }
        self.started
            .send(())
            .map_err(|error| chio_core_types::Error::InvalidSignature(error.to_string()))?;
        self.release
            .lock()
            .map_err(|_| {
                chio_core_types::Error::InvalidSignature("release lock poisoned".to_string())
            })?
            .recv()
            .map_err(|error| chio_core_types::Error::InvalidSignature(error.to_string()))?;
        self.inner.sign_bytes(message)
    }
}

#[test]
fn activation_waits_until_inflight_signature_is_durably_anchored() {
    let directory = tempfile::tempdir().test_unwrap();
    let ready = ready_log(&trusted_temp_path(&directory, "race.sqlite"));
    let (started_tx, started_rx) = sync_channel(0);
    let (release_tx, release_rx) = sync_channel(0);
    let blocking = BlockingBackend {
        inner: ready.old.clone(),
        started: started_tx,
        release: Mutex::new(release_rx),
        blocked_once: AtomicBool::new(false),
    };
    let router = Arc::new(
        KeyringSigningRouter::open(Arc::clone(&ready.store), Box::new(blocking)).test_unwrap(),
    );
    let staged = router
        .stage_pending(
            ready.rotation.body.event_id.clone(),
            Box::new(ready.new.clone()),
        )
        .test_unwrap();

    let signer = Arc::clone(&router);
    let sign_thread =
        std::thread::spawn(move || signer.sign_canonical(0, &serde_json::json!({"race": true})));
    started_rx.recv().test_unwrap();

    let activator = Arc::clone(&router);
    let checkpoint_hash = ready.checkpoint_hash;
    let operator = ready.operator.clone();
    let (activated_tx, activated_rx) = sync_channel(1);
    let activation_thread = std::thread::spawn(move || {
        let mut staged = staged;
        let result = activator.activate_rotation(&mut staged, &checkpoint_hash, &operator);
        activated_tx.send(result).test_unwrap();
    });
    assert!(activated_rx
        .recv_timeout(Duration::from_millis(100))
        .is_err());

    release_tx.send(()).test_unwrap();
    let evidence = sign_thread.join().test_unwrap().test_unwrap();
    assert_eq!(evidence.signing_epoch, 0);
    activated_rx
        .recv_timeout(Duration::from_secs(2))
        .test_unwrap()
        .test_unwrap();
    activation_thread.join().test_unwrap();
    assert_eq!(
        ready.store.load_artifact_signatures().test_unwrap(),
        vec![evidence]
    );
    router
        .sign_canonical(1, &serde_json::json!({"after": true}))
        .test_unwrap();
}

#[test]
fn failed_durable_anchor_never_returns_signature_evidence() {
    let directory = tempfile::tempdir().test_unwrap();
    let path = trusted_temp_path(&directory, "failure.sqlite");
    let ready = ready_log(&path);
    let router =
        KeyringSigningRouter::open(Arc::clone(&ready.store), Box::new(ready.old)).test_unwrap();
    rusqlite::Connection::open(&path)
        .test_unwrap()
        .execute_batch(
            "CREATE TRIGGER fail_artifact_anchor BEFORE INSERT ON key_artifact_signatures BEGIN SELECT RAISE(ABORT, 'injected'); END;",
        )
        .test_unwrap();

    assert!(router
        .sign_canonical(0, &serde_json::json!({"must": "persist"}))
        .is_err());
    assert!(ready
        .store
        .load_artifact_signatures()
        .test_unwrap()
        .is_empty());
}

#[test]
fn enterprise_router_returns_one_identity_epoch_signature_and_anchor_result() {
    let directory = tempfile::tempdir().test_unwrap();
    let ready = ready_log(&trusted_temp_path(&directory, "atomic-result.sqlite"));
    let expected_public_key = ready.old.public_key();
    let router = KeyringSigningRouter::open_enterprise(
        Arc::clone(&ready.store),
        Box::new(ready.old.clone()),
        ready.artifact_time_anchor_id.clone(),
        Arc::new(ready.artifact_time_signer.clone()),
    )
    .test_unwrap();

    let artifact = b"authority artifact with embedded identity";
    let result = router
        .sign_bytes_for_identity(&expected_public_key, artifact)
        .test_unwrap();
    assert_eq!(result.public_key, expected_public_key);
    assert_eq!(result.algorithm, expected_public_key.algorithm());
    assert_eq!(result.signing_epoch, 0);
    assert_eq!(result.signature, result.evidence.artifact_signature);
    assert!(result.public_key.verify(artifact, &result.signature));
    assert!(result.time_anchor.is_some());
    assert!(router
        .sign_bytes_for_identity(&ready.new.public_key(), artifact)
        .is_err());
}

#[test]
fn enterprise_time_anchor_keeps_pre_rotation_artifact_verifiable_after_reopen() {
    let directory = tempfile::tempdir().test_unwrap();
    let path = trusted_temp_path(&directory, "historical-verification.sqlite");
    let ready = ready_log(&path);
    let old_public_key = ready.old.public_key();
    let policy = ready.policy.clone();
    let router = KeyringSigningRouter::open_enterprise(
        Arc::clone(&ready.store),
        Box::new(ready.old.clone()),
        ready.artifact_time_anchor_id.clone(),
        Arc::new(ready.artifact_time_signer.clone()),
    )
    .test_unwrap();
    let artifact = b"artifact issued before witnessed rotation";
    let signed = router.sign_bytes_with_identity(artifact).test_unwrap();
    ready
        .store
        .activate_rotation(
            &ready.rotation.body.event_id,
            &ready.checkpoint_hash,
            &ready.operator,
        )
        .test_unwrap();

    assert_eq!(signed.signing_epoch, 0);
    assert_eq!(
        ready
            .store
            .load_state()
            .test_unwrap()
            .test_unwrap()
            .signing_epoch(),
        1
    );
    ready
        .store
        .verify_artifact_with_trusted_time(artifact, &old_public_key, &signed.signature)
        .test_unwrap();
    drop(router);
    drop(ready.store);

    let reopened = SqliteKeyLogStore::open(&path, policy).test_unwrap();
    reopened
        .verify_artifact_with_trusted_time(artifact, &old_public_key, &signed.signature)
        .test_unwrap();
}

#[test]
fn remote_verifier_accepts_pre_activation_anchor_and_rejects_post_activation_or_invented_context() {
    let directory = tempfile::tempdir().test_unwrap();
    let ready = ready_log(&trusted_temp_path(
        &directory,
        "remote-artifact-source.sqlite",
    ));
    let old_key_id = derive_key_id(ready.old.algorithm(), &ready.old.public_key()).test_unwrap();
    let router = KeyringSigningRouter::open_enterprise(
        Arc::clone(&ready.store),
        Box::new(ready.old.clone()),
        ready.artifact_time_anchor_id.clone(),
        Arc::new(ready.artifact_time_signer.clone()),
    )
    .test_unwrap();
    let artifact = b"issuance response finalized before activation";
    let signed = router.sign_bytes_with_identity(artifact).test_unwrap();
    let pre_activation_anchor = signed.time_anchor.clone().test_unwrap();
    let state = ready
        .store
        .activate_rotation(
            &ready.rotation.body.event_id,
            &ready.checkpoint_hash,
            &ready.operator,
        )
        .test_unwrap();
    let deactivated_at = state
        .key(&old_key_id)
        .test_unwrap()
        .deactivated_at
        .test_unwrap();
    assert!(pre_activation_anchor.body.anchored_at < deactivated_at);

    let verifier = SqlitePinnedKeyLogVerifier::provision(
        trusted_temp_path(&directory, "remote-artifact-verifier.sqlite"),
        ready.policy.clone(),
        Arc::new(FixedClock(deactivated_at + 10)),
    )
    .test_unwrap();
    verifier
        .apply_sync(&ready.store.synchronization_response(None).test_unwrap())
        .test_unwrap();
    let record = verifier
        .verify_artifact_signing_evidence(artifact, &signed.evidence, &pre_activation_anchor)
        .test_unwrap();
    assert_eq!(record.public_key, ready.old.public_key());

    let mut post_activation_body = pre_activation_anchor.body.clone();
    post_activation_body.anchored_at = deactivated_at;
    let post_activation_anchor =
        SignedArtifactTimeAnchor::sign(post_activation_body, &ready.artifact_time_signer)
            .test_unwrap();
    assert!(verifier
        .verify_artifact_signing_evidence(artifact, &signed.evidence, &post_activation_anchor,)
        .is_err());

    let mut invented_context_body = pre_activation_anchor.body;
    invented_context_body.anchor = ArtifactTimeAnchorKind::KeyLogCheckpoint {
        checkpoint_sequence: 999,
        checkpoint_hash: chio_core_types::sha256(b"invented checkpoint"),
    };
    let invented_context_anchor =
        SignedArtifactTimeAnchor::sign(invented_context_body, &ready.artifact_time_signer)
            .test_unwrap();
    assert!(verifier
        .verify_artifact_signing_evidence(artifact, &signed.evidence, &invented_context_anchor,)
        .is_err());
}

#[test]
fn enterprise_router_rejects_unguarded_activation_and_standard_runtime() {
    let directory = tempfile::tempdir().test_unwrap();
    let ready = ready_log(&trusted_temp_path(
        &directory,
        "enterprise-downgrade.sqlite",
    ));
    let router = Arc::new(
        KeyringSigningRouter::open_enterprise(
            Arc::clone(&ready.store),
            Box::new(ready.old.clone()),
            ready.artifact_time_anchor_id.clone(),
            Arc::new(ready.artifact_time_signer.clone()),
        )
        .test_unwrap(),
    );

    assert!(WitnessedRotationRuntime::new(
        Arc::clone(&ready.store),
        Arc::clone(&router),
        Arc::new(ready.operator.clone()),
    )
    .is_err());

    let mut staged = router
        .stage_pending(
            ready.rotation.body.event_id.clone(),
            Box::new(ready.new.clone()),
        )
        .test_unwrap();
    assert!(router
        .activate_rotation(&mut staged, &ready.checkpoint_hash, &ready.operator)
        .is_err());
    assert_eq!(router.signing_epoch().test_unwrap(), 0);
    assert_eq!(
        router.active_public_key().test_unwrap(),
        ready.old.public_key()
    );

    let standard_ready = ready_log(&trusted_temp_path(
        &directory,
        "standard-enterprise-upgrade.sqlite",
    ));
    let standard_router = Arc::new(
        KeyringSigningRouter::open(
            Arc::clone(&standard_ready.store),
            Box::new(standard_ready.old.clone()),
        )
        .test_unwrap(),
    );
    assert!(WitnessedRotationRuntime::new_enterprise(
        Arc::clone(&standard_ready.store),
        standard_router,
        Arc::new(standard_ready.operator),
        Arc::new(AcceptingEnterpriseReceiptSink),
        Arc::new(AcceptingActivationGuard),
    )
    .is_err());
}

#[test]
fn enterprise_anchor_insert_failure_rolls_back_the_artifact_signature() {
    let directory = tempfile::tempdir().test_unwrap();
    let path = trusted_temp_path(&directory, "anchor-rollback.sqlite");
    let ready = ready_log(&path);
    let router = KeyringSigningRouter::open_enterprise(
        Arc::clone(&ready.store),
        Box::new(ready.old.clone()),
        ready.artifact_time_anchor_id.clone(),
        Arc::new(ready.artifact_time_signer.clone()),
    )
    .test_unwrap();
    rusqlite::Connection::open(&path)
        .test_unwrap()
        .execute_batch(
            "CREATE TRIGGER fail_time_anchor BEFORE INSERT ON key_artifact_time_anchors BEGIN SELECT RAISE(ABORT, 'injected'); END;",
        )
        .test_unwrap();

    assert!(router
        .sign_bytes_with_identity(b"signature and anchor must commit together")
        .is_err());
    assert!(ready
        .store
        .load_artifact_signatures()
        .test_unwrap()
        .is_empty());
    let anchor_count = rusqlite::Connection::open(&path)
        .test_unwrap()
        .query_row(
            "SELECT COUNT(*) FROM key_artifact_time_anchors",
            [],
            |row| row.get::<_, i64>(0),
        )
        .test_unwrap();
    assert_eq!(anchor_count, 0);
}

#[test]
fn enterprise_router_rejects_legacy_artifact_without_trusted_time() {
    let directory = tempfile::tempdir().test_unwrap();
    let ready = ready_log(&trusted_temp_path(&directory, "legacy-artifact.sqlite"));
    let legacy = KeyringSigningRouter::open(Arc::clone(&ready.store), Box::new(ready.old.clone()))
        .test_unwrap();
    legacy
        .sign_bytes_with_identity(b"legacy artifact without a time anchor")
        .test_unwrap();
    drop(legacy);

    assert!(KeyringSigningRouter::open_enterprise(
        Arc::clone(&ready.store),
        Box::new(ready.old.clone()),
        ready.artifact_time_anchor_id,
        Arc::new(ready.artifact_time_signer),
    )
    .is_err());
}
