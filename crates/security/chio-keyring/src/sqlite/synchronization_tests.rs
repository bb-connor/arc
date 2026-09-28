use super::*;
use crate::{
    derive_key_id, AuthorityId, BootstrapAuthorization, KeyLogAuthorizations, KeyLogEventBody,
    KeyLogOperation, KeyLogPolicyConfig, LogId, NewKeyProofOfPossession, OldKeyAuthorization,
    RecoveryPolicyId, WitnessRosterId, KEY_LOG_EVENT_SCHEMA,
};
use chio_core_types::{Ed25519Backend, Keypair};
use chio_test_support::prelude::*;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};

#[path = "../../tests/support/mod.rs"]
mod support;

struct FixedClock;

impl chio_security_types::clock::Clock for FixedClock {
    fn read(
        &self,
    ) -> core::result::Result<
        chio_security_types::clock::ClockReading,
        chio_security_types::clock::ClockError,
    > {
        let value = 5_000;
        chio_security_types::clock::Clock::read(
            &chio_security_types::clock::FixedClock::from_millis(value),
        )
    }
}

struct AppendDuringRead {
    writer: Arc<SqliteKeyLogStore>,
    operator: Ed25519Backend,
    rotation: SignedKeyLogEvent,
    pending: AtomicBool,
}

impl chio_security_types::clock::Clock for AppendDuringRead {
    fn read(
        &self,
    ) -> core::result::Result<
        chio_security_types::clock::ClockReading,
        chio_security_types::clock::ClockError,
    > {
        let value: Result<u64> = (|| {
            if self.pending.swap(false, Ordering::SeqCst) {
                self.writer.append_event(&self.rotation, &self.operator)?;
            }
            Ok(5_000)
        })();
        let value = value.map_err(|_| chio_security_types::clock::ClockError::Unavailable)?;
        chio_security_types::clock::Clock::read(
            &chio_security_types::clock::FixedClock::from_millis(value),
        )
    }
}

fn backend(seed: u8) -> Ed25519Backend {
    Ed25519Backend::new(Keypair::from_seed(&[seed; 32]))
}

#[test]
fn synchronization_page_and_head_share_a_snapshot_during_concurrent_append() {
    let directory = support::private_tempdir().test_unwrap();
    let path = support::trusted_temp_path(&directory, "keylog.sqlite");
    let bootstrap = backend(1);
    let operator = backend(2);
    let active = backend(3);
    let next = backend(4);
    let witnesses = [backend(10), backend(11), backend(12)];
    let policy = KeyLogPolicy::new(KeyLogPolicyConfig {
        log_id: LogId::new("log.snapshot").test_unwrap(),
        authority_id: AuthorityId::new("authority.snapshot").test_unwrap(),
        bootstrap_key: bootstrap.public_key(),
        operator_key: operator.public_key(),
        witness_roster_id: WitnessRosterId::new("roster.snapshot").test_unwrap(),
        witness_keys: witnesses
            .iter()
            .enumerate()
            .map(|(index, witness)| {
                (
                    WitnessId::new(format!("witness.{index}")).test_unwrap(),
                    witness.public_key(),
                )
            })
            .collect(),
        recovery_policy_id: RecoveryPolicyId::new("recovery.snapshot").test_unwrap(),
        recovery_keys: BTreeMap::new(),
        recovery_threshold: 0,
        max_checkpoint_future_skew: 100,
    })
    .test_unwrap();
    let writer = Arc::new(
        SqliteKeyLogStore::open_with_clock(
            &path,
            policy.clone(),
            SigningTopology::LocalSingleWriter,
            Arc::new(FixedClock),
        )
        .test_unwrap(),
    );
    let genesis_body = KeyLogEventBody {
        schema: KEY_LOG_EVENT_SCHEMA.to_owned(),
        log_id: policy.log_id().clone(),
        sequence: 0,
        event_id: EventId::new("event.genesis").test_unwrap(),
        previous_event_hash: None,
        authority_id: policy.authority_id().clone(),
        key_id: derive_key_id(active.algorithm(), &active.public_key()).test_unwrap(),
        algorithm: active.algorithm(),
        public_key: active.public_key(),
        operation: KeyLogOperation::Genesis,
        effective_at: 1_000,
        verify_until: None,
        reason: None,
        issued_at: 1_000,
    };
    let genesis = SignedKeyLogEvent {
        authorizations: KeyLogAuthorizations::bootstrap(
            BootstrapAuthorization::sign(&genesis_body, &bootstrap).test_unwrap(),
        ),
        body: genesis_body,
    };
    let checkpoint = writer.append_event(&genesis, &operator).test_unwrap();
    for (index, witness) in witnesses.iter().take(2).enumerate() {
        let signature = WitnessSignature::sign(
            &checkpoint,
            WitnessId::new(format!("witness.{index}")).test_unwrap(),
            witness,
        )
        .test_unwrap();
        writer
            .store_witness_signature(&checkpoint.checkpoint_hash().test_unwrap(), &signature)
            .test_unwrap();
    }
    let initial_pin = writer.head_pin().test_unwrap().test_unwrap();
    let mut rotation_body = genesis.body.clone();
    rotation_body.sequence = 1;
    rotation_body.event_id = EventId::new("event.rotation").test_unwrap();
    rotation_body.previous_event_hash = Some(genesis.envelope_hash().test_unwrap());
    rotation_body.key_id = derive_key_id(next.algorithm(), &next.public_key()).test_unwrap();
    rotation_body.public_key = next.public_key();
    rotation_body.operation = KeyLogOperation::Rotate {
        previous_key_id: genesis.body.key_id,
        witness_roster_id: WitnessRosterId::new("roster.snapshot").test_unwrap(),
        witness_roster_binding: policy.witness_roster_binding().test_unwrap(),
    };
    rotation_body.issued_at = 2_000;
    rotation_body.effective_at = 2_000;
    rotation_body.verify_until = Some(9_000);
    let rotation = SignedKeyLogEvent {
        authorizations: KeyLogAuthorizations::rotation(
            OldKeyAuthorization::sign(&rotation_body, &active).test_unwrap(),
            NewKeyProofOfPossession::sign(&rotation_body, &next).test_unwrap(),
        ),
        body: rotation_body,
    };
    let mut observer = SqliteKeyLogStore::open_observer(&path, policy).test_unwrap();
    // The clock deterministically commits on a separate SQLite connection
    // during the observer read. No timing, retries or test-only production hook.
    observer.clock = Arc::new(AppendDuringRead {
        writer: Arc::clone(&writer),
        operator,
        rotation,
        pending: AtomicBool::new(true),
    });
    let snapshot = observer
        .synchronization_snapshot(Some(&initial_pin))
        .test_unwrap();
    assert!(snapshot.response.event_envelopes.is_empty());
    assert!(snapshot.response.checkpoints.is_empty());
    assert_eq!(snapshot.head, initial_pin);
    assert_eq!(snapshot.head_stage, CheckpointStage::Witnessed);
    assert_eq!(writer.head_pin().test_unwrap().test_unwrap().tree_size, 2);
    let next = observer
        .synchronization_snapshot(Some(&snapshot.head))
        .test_unwrap();
    assert_eq!(next.response.event_envelopes.len(), 1);
    assert_eq!(next.response.checkpoints.len(), 1);
    assert_eq!(next.head.tree_size, 2);
    assert_eq!(next.head_stage, CheckpointStage::Pending);
}
