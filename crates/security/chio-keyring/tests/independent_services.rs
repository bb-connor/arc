#![cfg(unix)]

use chio_test_support::prelude::*;

use std::collections::BTreeMap;
use std::fs::Permissions;
use std::io::{Cursor, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chio_core_types::{Ed25519Backend, Keypair, SigningBackend};
use chio_keyring::{
    derive_key_id, read_canonical_frame, read_single_canonical_frame,
    validate_independent_operation_readiness, write_canonical_frame, AuditServiceConfig,
    AuthorityId, BootstrapAuthorization, EventId, EventReason, KeyLogAuthorizations,
    KeyLogEventBody, KeyLogOperation, KeyLogPolicyDocument, KeyringSigningRouter, LogId,
    NewKeyProofOfPossession, OldKeyAuthorization, UnixKeyLogAuditClient, UnixKeyLogWitnessClient,
    WitnessRosterId, WitnessServiceConfig, WitnessedRotationRuntime, KEY_LOG_EVENT_SCHEMA,
    KEY_LOG_POLICY_DOCUMENT_SCHEMA, KEY_LOG_WITNESS_SERVICE_CONFIG_SCHEMA,
    MAX_KEY_LOG_IPC_FRAME_BYTES,
};

mod support;

use support::{private_tempdir, trusted_temp_path, write_private_file};

const WAIT_LIMIT: Duration = Duration::from_secs(10);

fn backend(seed: u8) -> Ed25519Backend {
    Ed25519Backend::new(Keypair::from_seed(&[seed; 32]))
}

struct Children(Vec<Child>);

struct AcceptingEnterpriseReceiptSink;

impl chio_keyring::KeyEnterpriseReceiptSink for AcceptingEnterpriseReceiptSink {
    fn persist(
        &self,
        _receipt: &chio_keyring::SignedKeyEnterpriseReceipt,
    ) -> chio_keyring::Result<()> {
        Ok(())
    }
}

struct TestActivationGuard {
    allowed: AtomicBool,
    calls: AtomicUsize,
}

impl chio_keyring::KeyLogActivationGuard for TestActivationGuard {
    fn require_activation(&self) -> chio_keyring::Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.allowed.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(chio_keyring::KeyringError::StateInvariant(
                "test migration binding denied selector activation",
            ))
        }
    }
}

impl Drop for Children {
    fn drop(&mut self) {
        for child in &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

struct Fixture {
    directory: tempfile::TempDir,
    policy_path: PathBuf,
    operator: Ed25519Backend,
    active: Ed25519Backend,
    artifact_time: Ed25519Backend,
    witness_backends: [Ed25519Backend; 3],
    audit_backends: [Ed25519Backend; 2],
    witness_ids: [&'static str; 3],
}

impl Fixture {
    fn new() -> Self {
        let directory = private_tempdir().test_unwrap();
        let bootstrap = backend(1);
        let operator = backend(2);
        let active = backend(3);
        let witness_backends = [backend(10), backend(11), backend(12)];
        let audit_backends = [backend(30), backend(31)];
        let artifact_time = backend(20);
        let witness_ids = ["witness.a", "witness.b", "witness.c"];
        let policy_path = trusted_temp_path(&directory, "policy.json");
        let policy = KeyLogPolicyDocument {
            schema: KEY_LOG_POLICY_DOCUMENT_SCHEMA.to_string(),
            log_id: "log.independent.processes".to_string(),
            authority_id: "authority.independent.processes".to_string(),
            bootstrap_public_key: bootstrap.public_key().to_hex(),
            operator_public_key: operator.public_key().to_hex(),
            witness_roster_id: "roster.independent.v1".to_string(),
            witness_public_keys: BTreeMap::from([
                (
                    witness_ids[0].to_string(),
                    witness_backends[0].public_key().to_hex(),
                ),
                (
                    witness_ids[1].to_string(),
                    witness_backends[1].public_key().to_hex(),
                ),
                (
                    witness_ids[2].to_string(),
                    witness_backends[2].public_key().to_hex(),
                ),
            ]),
            recovery_policy_id: "recovery.independent.v1".to_string(),
            recovery_public_keys: BTreeMap::new(),
            recovery_threshold: 0,
            artifact_time_public_keys: BTreeMap::from([(
                "clock.independent.v1".to_string(),
                artifact_time.public_key().to_hex(),
            )]),
            auditor_public_keys: BTreeMap::from([
                (
                    "audit.a".to_string(),
                    audit_backends[0].public_key().to_hex(),
                ),
                (
                    "audit.b".to_string(),
                    audit_backends[1].public_key().to_hex(),
                ),
            ]),
            max_checkpoint_future_skew_millis: 60_000,
        };
        write_private_file(&policy_path, serde_json::to_vec(&policy).test_unwrap()).test_unwrap();
        Self {
            directory,
            policy_path,
            operator,
            active,
            artifact_time,
            witness_backends,
            audit_backends,
            witness_ids,
        }
    }

    fn path(&self, relative_path: impl AsRef<std::path::Path>) -> PathBuf {
        trusted_temp_path(&self.directory, relative_path)
    }

    fn witness_config(&self, index: usize, provision: bool) -> PathBuf {
        let seed_path = self.path(format!("witness-{index}.seed"));
        if !seed_path.exists() {
            write_private_file(&seed_path, [10_u8 + u8::try_from(index).test_unwrap(); 32])
                .test_unwrap();
            std::fs::set_permissions(&seed_path, Permissions::from_mode(0o600)).test_unwrap();
        }
        let config_path = self.path(format!("witness-{index}.json"));
        let config = WitnessServiceConfig {
            schema: KEY_LOG_WITNESS_SERVICE_CONFIG_SCHEMA.to_string(),
            policy_path: self.policy_path.clone(),
            database_path: self.path(format!("witness-{index}.sqlite")),
            socket_path: self.path(format!("witness-{index}.sock")),
            witness_id: self.witness_ids[index].to_string(),
            seed_file_path: seed_path,
            provision,
        };
        write_private_file(
            config_path.as_path(),
            serde_json::to_vec(&config).test_unwrap(),
        )
        .test_unwrap();
        config_path
    }

    fn witness_client(&self, index: usize) -> UnixKeyLogWitnessClient {
        let policy = chio_keyring::load_key_log_policy(&self.policy_path).test_unwrap();
        UnixKeyLogWitnessClient::new(
            self.path(format!("witness-{index}.sock")),
            chio_keyring::WitnessId::new(self.witness_ids[index]).test_unwrap(),
            self.witness_backends[index].public_key(),
            policy.configuration_binding().test_unwrap(),
        )
        .test_unwrap()
    }

    fn spawn_witness(&self, index: usize, provision: bool) -> Child {
        let config = self.witness_config(index, provision);
        Command::new(env!("CARGO_BIN_EXE_chio-keylog-witness"))
            .arg("--config")
            .arg(config)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .test_unwrap()
    }

    fn audit_seed_path(&self, index: usize) -> PathBuf {
        let seed_path = self.path(format!("audit-{index}.seed"));
        if !seed_path.exists() {
            write_private_file(&seed_path, [30_u8 + u8::try_from(index).test_unwrap(); 32])
                .test_unwrap();
            std::fs::set_permissions(&seed_path, Permissions::from_mode(0o600)).test_unwrap();
        }
        seed_path
    }
}

fn wait_for_witness(
    client: &UnixKeyLogWitnessClient,
    nonce: &str,
) -> chio_keyring::WitnessServiceReadinessProof {
    let started = Instant::now();
    loop {
        if let Ok(proof) = client.readiness(nonce) {
            return proof;
        }
        assert!(
            started.elapsed() < WAIT_LIMIT,
            "witness did not become ready"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

fn now_millis() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .test_unwrap()
            .as_millis(),
    )
    .test_unwrap()
}

#[test]
fn canonical_framing_rejects_noncanonical_oversized_and_truncated_messages() {
    let mut encoded = Vec::new();
    write_canonical_frame(&mut encoded, &serde_json::json!({"a": 1, "b": 2})).test_unwrap();
    let decoded: serde_json::Value = read_canonical_frame(&mut Cursor::new(encoded)).test_unwrap();
    assert_eq!(decoded, serde_json::json!({"a": 1, "b": 2}));

    let noncanonical = b"{ \"a\": 1 }";
    let mut framed = Vec::new();
    framed.extend_from_slice(
        &u32::try_from(noncanonical.len())
            .test_unwrap()
            .to_be_bytes(),
    );
    framed.extend_from_slice(noncanonical);
    assert!(read_canonical_frame::<_, serde_json::Value>(&mut Cursor::new(framed)).is_err());

    let oversized = u32::try_from(MAX_KEY_LOG_IPC_FRAME_BYTES + 1)
        .test_unwrap()
        .to_be_bytes();
    assert!(read_canonical_frame::<_, serde_json::Value>(&mut Cursor::new(oversized)).is_err());

    let mut truncated = Vec::from(12_u32.to_be_bytes());
    truncated.extend_from_slice(b"{}{}");
    assert!(read_canonical_frame::<_, serde_json::Value>(&mut Cursor::new(truncated)).is_err());

    let mut trailing = Vec::new();
    write_canonical_frame(&mut trailing, &serde_json::json!({"only": "frame"})).test_unwrap();
    trailing.push(0);
    assert!(
        read_single_canonical_frame::<_, serde_json::Value>(&mut Cursor::new(trailing)).is_err()
    );
}

#[test]
fn three_witness_processes_prove_distinct_durable_identity_and_restart_recovery() {
    let fixture = Fixture::new();
    let mut children = Children(
        (0..3)
            .map(|index| fixture.spawn_witness(index, true))
            .collect(),
    );
    let clients = (0..3)
        .map(|index| fixture.witness_client(index))
        .collect::<Vec<_>>();
    let proofs = clients
        .iter()
        .enumerate()
        .map(|(index, client)| wait_for_witness(client, &format!("initial-{index}")))
        .collect::<Vec<_>>();
    let policy = chio_keyring::load_key_log_policy(&fixture.policy_path).test_unwrap();
    validate_independent_operation_readiness(
        &policy,
        &proofs,
        &[],
        &proofs
            .iter()
            .map(|proof| (proof.body.witness_id.clone(), proof.body.nonce.clone()))
            .collect(),
        &BTreeMap::from([
            ("audit.a".to_string(), "unused-audit-a".to_string()),
            ("audit.b".to_string(), "unused-audit-b".to_string()),
        ]),
        None,
        None,
    )
    .test_unwrap_err();
    assert!(proofs[0]
        .verify(
            &chio_keyring::WitnessId::new(fixture.witness_ids[0]).test_unwrap(),
            &fixture.witness_backends[0].public_key(),
            policy.configuration_binding().test_unwrap(),
            "different-challenge",
        )
        .is_err());
    let rebound_client = UnixKeyLogWitnessClient::new(
        fixture.path("witness-0.sock"),
        chio_keyring::WitnessId::new(fixture.witness_ids[1]).test_unwrap(),
        fixture.witness_backends[1].public_key(),
        policy.configuration_binding().test_unwrap(),
    )
    .test_unwrap();
    assert!(rebound_client.readiness("identity-rebinding").is_err());

    let process_ids = proofs
        .iter()
        .map(|proof| proof.body.process_id)
        .collect::<std::collections::BTreeSet<_>>();
    let storage_ids = proofs
        .iter()
        .map(|proof| proof.body.storage_identity)
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(process_ids.len(), 3);
    assert_eq!(storage_ids.len(), 3);

    let before = proofs[1].clone();
    children.0[1].kill().test_unwrap();
    children.0[1].wait().test_unwrap();
    children.0[1] = fixture.spawn_witness(1, false);
    let after = wait_for_witness(&clients[1], "restart-witness-b");
    assert_ne!(before.body.process_id, after.body.process_id);
    assert_eq!(before.body.storage_identity, after.body.storage_identity);
    assert_eq!(before.body.pin, after.body.pin);

    drop(UnixStream::connect(clients[0].socket_path()).test_unwrap());
    let mut truncated = UnixStream::connect(clients[0].socket_path()).test_unwrap();
    truncated.write_all(&64_u32.to_be_bytes()).test_unwrap();
    truncated.write_all(b"{}").test_unwrap();
    drop(truncated);
    wait_for_witness(&clients[0], "listener-survived-malformed-request");
}

#[test]
fn two_autonomous_auditors_rebuild_and_retain_the_same_witnessed_view() {
    let fixture = Fixture::new();
    let mut children = Children(
        (0..3)
            .map(|index| fixture.spawn_witness(index, true))
            .collect(),
    );
    let witness_clients = (0..3)
        .map(|index| fixture.witness_client(index))
        .collect::<Vec<_>>();
    for (index, client) in witness_clients.iter().enumerate() {
        wait_for_witness(client, &format!("audit-setup-{index}"));
    }

    let policy = chio_keyring::load_key_log_policy(&fixture.policy_path).test_unwrap();
    let operator_path = fixture.path("operator.sqlite");
    let store = Arc::new(
        chio_keyring::SqliteKeyLogStore::open(&operator_path, policy.clone()).test_unwrap(),
    );
    let issued_at = now_millis();
    let body = KeyLogEventBody {
        schema: KEY_LOG_EVENT_SCHEMA.to_string(),
        log_id: LogId::new("log.independent.processes").test_unwrap(),
        sequence: 0,
        event_id: EventId::new("event.independent.genesis").test_unwrap(),
        previous_event_hash: None,
        authority_id: AuthorityId::new("authority.independent.processes").test_unwrap(),
        key_id: derive_key_id(fixture.active.algorithm(), &fixture.active.public_key())
            .test_unwrap(),
        algorithm: fixture.active.algorithm(),
        public_key: fixture.active.public_key(),
        operation: KeyLogOperation::Genesis,
        effective_at: issued_at,
        verify_until: None,
        reason: Some(EventReason::new("independent service genesis").test_unwrap()),
        issued_at,
    };
    let event = chio_keyring::SignedKeyLogEvent {
        authorizations: KeyLogAuthorizations::bootstrap(
            BootstrapAuthorization::sign(&body, &backend(1)).test_unwrap(),
        ),
        body,
    };
    let checkpoint = store.append_event(&event, &fixture.operator).test_unwrap();
    let checkpoint_hash = checkpoint.checkpoint_hash().test_unwrap();
    for client in witness_clients.iter().take(2) {
        let response = store.synchronization_response(None).test_unwrap();
        let signature =
            chio_keyring::KeyLogWitnessClient::sign_candidate(client, &checkpoint, &response)
                .test_unwrap();
        store
            .store_witness_signature(&checkpoint_hash, &signature)
            .test_unwrap();
    }
    let expected_pin = store.head_pin().test_unwrap().test_unwrap();

    let mut audit_clients = Vec::new();
    let mut audit_config_paths = Vec::new();
    for index in 0..2 {
        let monitor_id = format!(
            "audit.{}",
            char::from(b'a' + u8::try_from(index).test_unwrap())
        );
        let socket_path = fixture.path(format!("audit-{index}.sock"));
        let config = AuditServiceConfig {
            schema: chio_keyring::KEY_LOG_AUDIT_SERVICE_CONFIG_SCHEMA.to_string(),
            policy_path: fixture.policy_path.clone(),
            database_path: fixture.path(format!("audit-{index}.sqlite")),
            operator_database_path: operator_path.clone(),
            socket_path: socket_path.clone(),
            monitor_id: monitor_id.clone(),
            seed_file_path: fixture.audit_seed_path(index),
            witness_sockets: BTreeMap::from([
                (
                    fixture.witness_ids[0].to_string(),
                    fixture.path("witness-0.sock"),
                ),
                (
                    fixture.witness_ids[1].to_string(),
                    fixture.path("witness-1.sock"),
                ),
                (
                    fixture.witness_ids[2].to_string(),
                    fixture.path("witness-2.sock"),
                ),
            ]),
            poll_interval_millis: 20,
            provision: true,
        };
        let config_path = fixture.path(format!("audit-{index}.json"));
        write_private_file(&config_path, serde_json::to_vec(&config).test_unwrap()).test_unwrap();
        audit_config_paths.push(config_path.clone());
        children.0.push(
            Command::new(env!("CARGO_BIN_EXE_chio-keylog-audit"))
                .arg("--config")
                .arg(config_path)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .test_unwrap(),
        );
        audit_clients.push(
            UnixKeyLogAuditClient::new(
                socket_path,
                monitor_id,
                fixture.audit_backends[index].public_key(),
                policy.configuration_binding().test_unwrap(),
            )
            .test_unwrap(),
        );
    }

    let audit_proofs = audit_clients
        .iter()
        .enumerate()
        .map(|(index, client)| {
            let started = Instant::now();
            loop {
                if let Ok(proof) = client.readiness(&format!("audit-ready-{index}")) {
                    break proof;
                }
                assert!(started.elapsed() < WAIT_LIMIT, "audit did not become ready");
                thread::sleep(Duration::from_millis(20));
            }
        })
        .collect::<Vec<_>>();
    let witness_proofs = witness_clients
        .iter()
        .enumerate()
        .map(|(index, client)| wait_for_witness(client, &format!("final-{index}")))
        .collect::<Vec<_>>();
    assert_eq!(
        witness_proofs
            .iter()
            .filter(|proof| proof.body.pin.as_ref() == Some(&expected_pin))
            .count(),
        2
    );
    assert_eq!(
        witness_proofs
            .iter()
            .filter(|proof| proof.body.pin.is_none())
            .count(),
        1
    );
    let witness_challenges = witness_proofs
        .iter()
        .map(|proof| (proof.body.witness_id.clone(), proof.body.nonce.clone()))
        .collect::<BTreeMap<_, _>>();
    let audit_challenges = audit_proofs
        .iter()
        .map(|proof| (proof.body.monitor_id.clone(), proof.body.nonce.clone()))
        .collect::<BTreeMap<_, _>>();
    validate_independent_operation_readiness(
        &policy,
        &witness_proofs,
        &audit_proofs,
        &witness_challenges,
        &audit_challenges,
        Some(&expected_pin),
        Some(&expected_pin),
    )
    .test_unwrap();
    let mut unrelated_witness_proofs = witness_proofs.clone();
    let mut unrelated_body = unrelated_witness_proofs[2].body.clone();
    let mut unrelated_pin = expected_pin.clone();
    unrelated_pin.signing_epoch = unrelated_pin.signing_epoch.checked_add(1).test_unwrap();
    unrelated_body.pin = Some(unrelated_pin);
    unrelated_witness_proofs[2] = chio_keyring::WitnessServiceReadinessProof::sign(
        unrelated_body,
        &fixture.witness_backends[2],
    )
    .test_unwrap();
    assert!(matches!(
        validate_independent_operation_readiness(
            &policy,
            &unrelated_witness_proofs,
            &audit_proofs,
            &witness_challenges,
            &audit_challenges,
            Some(&expected_pin),
            Some(&expected_pin),
        ),
        Err(chio_keyring::KeyringError::InvalidWitnessActivation)
    ));
    let mut replayed_audit_challenges = audit_challenges.clone();
    replayed_audit_challenges.insert("audit.a".to_string(), "fresh-audit-a-challenge".to_string());
    assert!(validate_independent_operation_readiness(
        &policy,
        &witness_proofs,
        &audit_proofs,
        &witness_challenges,
        &replayed_audit_challenges,
        Some(&expected_pin),
        Some(&expected_pin),
    )
    .is_err());
    assert_eq!(audit_proofs[0].body.pin.as_ref(), Some(&expected_pin));
    assert_eq!(audit_proofs[1].body.pin.as_ref(), Some(&expected_pin));
    assert_ne!(
        audit_proofs[0].body.storage_identity,
        audit_proofs[1].body.storage_identity
    );
    assert_ne!(
        audit_proofs[0].body.process_id,
        audit_proofs[1].body.process_id
    );
    audit_proofs[0]
        .verify(
            "audit.a",
            &fixture.audit_backends[0].public_key(),
            policy.configuration_binding().test_unwrap(),
            "audit-ready-0",
        )
        .test_unwrap();
    assert!(audit_proofs[0]
        .verify(
            "audit.a",
            &fixture.audit_backends[0].public_key(),
            policy.configuration_binding().test_unwrap(),
            "replayed-challenge",
        )
        .is_err());
    assert!(audit_proofs[0]
        .verify(
            "audit.a",
            &fixture.audit_backends[1].public_key(),
            policy.configuration_binding().test_unwrap(),
            "audit-ready-0",
        )
        .is_err());
    let mut forged = audit_proofs[0].clone();
    forged.body.pin = None;
    assert!(forged
        .verify(
            "audit.a",
            &fixture.audit_backends[0].public_key(),
            policy.configuration_binding().test_unwrap(),
            "audit-ready-0",
        )
        .is_err());

    drop(UnixStream::connect(audit_clients[1].socket_path()).test_unwrap());
    let mut truncated = UnixStream::connect(audit_clients[1].socket_path()).test_unwrap();
    truncated.write_all(&128_u32.to_be_bytes()).test_unwrap();
    truncated.write_all(b"{}").test_unwrap();
    drop(truncated);
    audit_clients[1]
        .readiness("audit-listener-survived")
        .test_unwrap();

    children.0[3].kill().test_unwrap();
    children.0[3].wait().test_unwrap();
    let mut restarted_config: AuditServiceConfig =
        serde_json::from_slice(&std::fs::read(&audit_config_paths[0]).test_unwrap()).test_unwrap();
    restarted_config.provision = false;
    write_private_file(
        &audit_config_paths[0],
        serde_json::to_vec(&restarted_config).test_unwrap(),
    )
    .test_unwrap();
    children.0[3] = Command::new(env!("CARGO_BIN_EXE_chio-keylog-audit"))
        .arg("--config")
        .arg(&audit_config_paths[0])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .test_unwrap();
    let started = Instant::now();
    let restarted = loop {
        if let Ok(proof) = audit_clients[0].readiness("audit-a-restart") {
            break proof;
        }
        assert!(
            started.elapsed() < WAIT_LIMIT,
            "restarted audit did not become ready"
        );
        thread::sleep(Duration::from_millis(20));
    };
    assert_ne!(audit_proofs[0].body.process_id, restarted.body.process_id);
    assert_eq!(
        audit_proofs[0].body.storage_identity,
        restarted.body.storage_identity
    );
    assert_eq!(audit_proofs[0].body.pin, restarted.body.pin);

    let witness_endpoints = BTreeMap::from([
        (
            chio_keyring::WitnessId::new(fixture.witness_ids[0]).test_unwrap(),
            fixture.path("witness-0.sock"),
        ),
        (
            chio_keyring::WitnessId::new(fixture.witness_ids[1]).test_unwrap(),
            fixture.path("witness-1.sock"),
        ),
        (
            chio_keyring::WitnessId::new(fixture.witness_ids[2]).test_unwrap(),
            fixture.path("witness-2.sock"),
        ),
    ]);
    let audit_endpoints = BTreeMap::from([
        ("audit.a".to_string(), fixture.path("audit-0.sock")),
        ("audit.b".to_string(), fixture.path("audit-1.sock")),
    ]);
    let (services, _) = chio_keyring::IndependentKeyLogServices::connect_and_validate(
        &policy,
        witness_endpoints,
        audit_endpoints,
        &expected_pin,
        &expected_pin,
    )
    .test_unwrap();
    let router = Arc::new(
        KeyringSigningRouter::open(Arc::clone(&store), Box::new(fixture.active.clone()))
            .test_unwrap(),
    );
    let runtime = WitnessedRotationRuntime::new(
        Arc::clone(&store),
        Arc::clone(&router),
        Arc::new(fixture.operator.clone()),
    )
    .test_unwrap();
    let rotated = backend(4);
    let rotation_issued_at = loop {
        let current = now_millis();
        if current > issued_at {
            break current;
        }
        thread::sleep(Duration::from_millis(1));
    };
    let rotation_body = KeyLogEventBody {
        schema: KEY_LOG_EVENT_SCHEMA.to_string(),
        log_id: event.body.log_id.clone(),
        sequence: 1,
        event_id: EventId::new("event.independent.rotation").test_unwrap(),
        previous_event_hash: Some(event.envelope_hash().test_unwrap()),
        authority_id: event.body.authority_id.clone(),
        key_id: derive_key_id(rotated.algorithm(), &rotated.public_key()).test_unwrap(),
        algorithm: rotated.algorithm(),
        public_key: rotated.public_key(),
        operation: KeyLogOperation::Rotate {
            previous_key_id: event.body.key_id,
            witness_roster_id: WitnessRosterId::new("roster.independent.v1").test_unwrap(),
            witness_roster_binding: policy.witness_roster_binding().test_unwrap(),
        },
        effective_at: rotation_issued_at,
        verify_until: Some(rotation_issued_at.checked_add(60_000).test_unwrap()),
        reason: Some(EventReason::new("independent service rotation").test_unwrap()),
        issued_at: rotation_issued_at,
    };
    let rotation = chio_keyring::SignedKeyLogEvent {
        authorizations: KeyLogAuthorizations::rotation(
            OldKeyAuthorization::sign(&rotation_body, &fixture.active).test_unwrap(),
            NewKeyProofOfPossession::sign(&rotation_body, &rotated).test_unwrap(),
        ),
        body: rotation_body,
    };
    let mut pending = runtime
        .begin_rotation(&rotation, Box::new(rotated.clone()))
        .test_unwrap();

    children.0[1].kill().test_unwrap();
    children.0[1].wait().test_unwrap();
    children.0[2].kill().test_unwrap();
    children.0[2].wait().test_unwrap();
    assert!(runtime
        .collect_witnesses_and_activate(&mut pending, &services)
        .is_err());
    assert_eq!(
        router.active_public_key().test_unwrap(),
        fixture.active.public_key()
    );

    drop(runtime);
    drop(router);
    drop(store);
    let store = Arc::new(
        chio_keyring::SqliteKeyLogStore::open_existing(&operator_path, policy.clone())
            .test_unwrap(),
    );
    assert_eq!(
        store.head_stage().test_unwrap(),
        Some(chio_keyring::CheckpointStage::Pending)
    );
    let router = Arc::new(
        KeyringSigningRouter::open_enterprise(
            Arc::clone(&store),
            Box::new(fixture.active.clone()),
            chio_keyring::AnchorId::new("clock.independent.v1").test_unwrap(),
            Arc::new(fixture.artifact_time.clone()),
        )
        .test_unwrap(),
    );
    let activation_guard = Arc::new(TestActivationGuard {
        allowed: AtomicBool::new(false),
        calls: AtomicUsize::new(0),
    });
    let runtime = WitnessedRotationRuntime::new_enterprise(
        Arc::clone(&store),
        Arc::clone(&router),
        Arc::new(fixture.operator.clone()),
        Arc::new(AcceptingEnterpriseReceiptSink),
        activation_guard.clone(),
    )
    .test_unwrap();
    let mut pending = runtime
        .resume_pending_rotation(Box::new(rotated.clone()))
        .test_unwrap();

    children.0[1] = fixture.spawn_witness(1, false);
    children.0[2] = fixture.spawn_witness(2, false);
    wait_for_witness(&witness_clients[1], "rotation-restart-b");
    wait_for_witness(&witness_clients[2], "rotation-restart-c");
    assert!(runtime
        .collect_witnesses_and_activate(&mut pending, &services)
        .is_err());
    assert_eq!(activation_guard.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        router.active_public_key().test_unwrap(),
        fixture.active.public_key()
    );
    activation_guard.allowed.store(true, Ordering::SeqCst);
    let outcome = runtime
        .collect_witnesses_and_activate(&mut pending, &services)
        .test_unwrap();
    assert_eq!(activation_guard.calls.load(Ordering::SeqCst), 3);
    assert_eq!(outcome.signing_epoch, 1);
    assert_eq!(outcome.audit_pin.signing_epoch, 1);
    assert_eq!(
        router.active_public_key().test_unwrap(),
        rotated.public_key()
    );
}
