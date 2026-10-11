//! Retained broker authority must follow current authenticated lifecycle state.
use super::*;
use chio_core_types::{Ed25519Backend, Keypair, SigningBackend};
use chio_kernel::CapabilityAuthority;
use chio_keyring::*;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

struct MutableClock {
    millis: AtomicU64,
    available: AtomicBool,
}

impl Clock for MutableClock {
    fn read(
        &self,
    ) -> std::result::Result<
        chio_security_types::clock::ClockReading,
        chio_security_types::clock::ClockError,
    > {
        if !self.available.load(Ordering::SeqCst) {
            return Err(chio_security_types::clock::ClockError::Unavailable);
        }
        chio_security_types::clock::FixedClock::from_millis(self.millis.load(Ordering::SeqCst))
            .read()
    }
}

struct Fixture {
    _directory: tempfile::TempDir,
    clock: Arc<MutableClock>,
    store: Arc<SqliteKeyLogStore>,
    operator: Ed25519Backend,
    old: Ed25519Backend,
    new: Ed25519Backend,
    genesis: SignedKeyLogEvent,
    rotation: SignedKeyLogEvent,
}

fn backend(seed: u8) -> Ed25519Backend {
    Ed25519Backend::new(Keypair::from_seed(&[seed; 32]))
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let directory = chio_test_support::private_tempdir()?;
        let bootstrap = backend(1);
        let operator = backend(2);
        let old = backend(3);
        let new = backend(4);
        let witness = backend(5);
        let witness_id = WitnessId::new("witness.retained-host")?;
        let policy = KeyLogPolicy::new(KeyLogPolicyConfig {
            log_id: LogId::new("log.retained-host")?,
            authority_id: AuthorityId::new("authority.retained-host")?,
            bootstrap_key: bootstrap.public_key(),
            operator_key: operator.public_key(),
            witness_roster_id: WitnessRosterId::new("roster.retained-host")?,
            witness_keys: BTreeMap::from([(witness_id.clone(), witness.public_key())]),
            recovery_policy_id: RecoveryPolicyId::new("recovery.retained-host")?,
            recovery_keys: BTreeMap::new(),
            recovery_threshold: 0,
            max_checkpoint_future_skew: 0,
        })?
        .with_auditor_roots(BTreeMap::from([
            ("audit.a".into(), backend(6).public_key()),
            ("audit.b".into(), backend(7).public_key()),
        ]))?;
        let clock = Arc::new(MutableClock {
            millis: AtomicU64::new(1_000),
            available: AtomicBool::new(true),
        });
        let store = Arc::new(SqliteKeyLogStore::open_with_clock(
            directory.path().join("keylog.db"),
            policy.clone(),
            SigningTopology::LocalSingleWriter,
            clock.clone(),
        )?);
        let body = KeyLogEventBody {
            schema: KEY_LOG_EVENT_SCHEMA.into(),
            log_id: policy.log_id().clone(),
            sequence: 0,
            event_id: EventId::new("event.genesis")?,
            previous_event_hash: None,
            authority_id: policy.authority_id().clone(),
            key_id: derive_key_id(old.algorithm(), &old.public_key())?,
            algorithm: old.algorithm(),
            public_key: old.public_key(),
            operation: KeyLogOperation::Genesis,
            effective_at: 1_000,
            verify_until: None,
            reason: None,
            issued_at: 1_000,
        };
        let genesis = SignedKeyLogEvent {
            authorizations: KeyLogAuthorizations::bootstrap(BootstrapAuthorization::sign(
                &body, &bootstrap,
            )?),
            body,
        };
        store.append_event(&genesis, &operator)?;
        clock.millis.store(2_000, Ordering::SeqCst);
        let body = KeyLogEventBody {
            schema: KEY_LOG_EVENT_SCHEMA.into(),
            log_id: policy.log_id().clone(),
            sequence: 1,
            event_id: EventId::new("event.rotation")?,
            previous_event_hash: Some(genesis.envelope_hash()?),
            authority_id: policy.authority_id().clone(),
            key_id: derive_key_id(new.algorithm(), &new.public_key())?,
            algorithm: new.algorithm(),
            public_key: new.public_key(),
            operation: KeyLogOperation::Rotate {
                previous_key_id: genesis.body.key_id,
                witness_roster_id: policy.witness_roster_id().clone(),
                witness_roster_binding: policy.witness_roster_binding()?,
            },
            effective_at: 2_000,
            verify_until: Some(9_000),
            reason: None,
            issued_at: 2_000,
        };
        let rotation = SignedKeyLogEvent {
            authorizations: KeyLogAuthorizations::rotation(
                OldKeyAuthorization::sign(&body, &old)?,
                NewKeyProofOfPossession::sign(&body, &new)?,
            ),
            body,
        };
        let checkpoint = store.append_event(&rotation, &operator)?;
        let hash = checkpoint.checkpoint_hash()?;
        store.store_witness_signature(
            &hash,
            &WitnessSignature::sign(&checkpoint, witness_id, &witness)?,
        )?;
        store.activate_rotation(&rotation.body.event_id, &hash, &operator)?;
        Ok(Self {
            _directory: directory,
            clock,
            store,
            operator,
            old,
            new,
            genesis,
            rotation,
        })
    }

    fn authority(&self) -> TestResult<ParentAuthority> {
        let store = self.store.clone();
        let clock = self.clock.clone();
        let live_key_log: Box<LiveKeyLog> = Box::new(move || {
            let state = store
                .load_state()
                .map_err(error)?
                .ok_or_else(|| error("missing witnessed state"))?;
            Ok((clock.unix_millis()?, state))
        });
        live_key_log()?;
        Ok(ParentAuthority {
            inner: chio_kernel::GovernedCapabilityAuthority::new(
                Arc::new(backend(4)),
                self.clock.clone(),
            ),
            live_key_log,
        })
    }

    fn terminal(&self, operation: KeyLogOperation) -> TestResult {
        self.clock.millis.store(4_000, Ordering::SeqCst);
        let body = KeyLogEventBody {
            schema: KEY_LOG_EVENT_SCHEMA.into(),
            log_id: self.genesis.body.log_id.clone(),
            sequence: 2,
            event_id: EventId::new("event.terminal")?,
            previous_event_hash: Some(self.rotation.envelope_hash()?),
            authority_id: self.genesis.body.authority_id.clone(),
            key_id: self.genesis.body.key_id,
            algorithm: self.old.algorithm(),
            public_key: self.old.public_key(),
            operation,
            effective_at: 4_000,
            verify_until: None,
            reason: None,
            issued_at: 4_000,
        };
        let event = SignedKeyLogEvent {
            authorizations: KeyLogAuthorizations {
                old_key: Some(OldKeyAuthorization::sign(&body, &self.new)?),
                ..KeyLogAuthorizations::default()
            },
            body,
        };
        self.store.append_event(&event, &self.operator)?;
        Ok(())
    }
}

#[test]
fn kg2_retained_host_excludes_key_at_owned_clock_deadline() -> TestResult {
    let fixture = Fixture::new()?;
    let authority = fixture.authority()?;
    assert!(authority
        .trusted_public_keys()
        .contains(&fixture.old.public_key()));
    fixture.clock.millis.store(9_000, Ordering::SeqCst);
    let state = fixture.store.load_state()?.ok_or("missing state")?;
    assert!(!state
        .witnessed_verification_keys_at(9_000)
        .iter()
        .any(|key| key.public_key == fixture.old.public_key()));
    assert!(
        !authority
            .trusted_public_keys()
            .contains(&fixture.old.public_key()),
        "retained authority cached the expired issuer"
    );
    assert!(
        authority
            .check_issuer_lifecycle(&fixture.old.public_key(), 1, 2)
            .is_err(),
        "caller time must not override owned deadline"
    );
    Ok(())
}

#[test]
fn kg2_retained_host_excludes_retired_and_revoked_keys() -> TestResult {
    for operation in [KeyLogOperation::Retire, KeyLogOperation::Revoke] {
        let fixture = Fixture::new()?;
        let authority = fixture.authority()?;
        fixture.terminal(operation)?;
        let state = fixture.store.load_state()?.ok_or("missing state")?;
        assert!(!state
            .witnessed_verification_keys_at(4_000)
            .iter()
            .any(|key| key.public_key == fixture.old.public_key()));
        assert!(
            !authority
                .trusted_public_keys()
                .contains(&fixture.old.public_key()),
            "retained authority cached terminal issuer"
        );
        assert!(authority
            .check_issuer_lifecycle(&fixture.old.public_key(), 1, 4)
            .is_err());
    }
    Ok(())
}

#[test]
fn kg2_retained_host_rejects_issuance_at_or_after_rotation_cutoff() -> TestResult {
    let fixture = Fixture::new()?;
    let authority = fixture.authority()?;
    authority.check_issuer_lifecycle(&fixture.old.public_key(), 1, 2)?;
    assert!(
        authority
            .check_issuer_lifecycle(&fixture.old.public_key(), 2, 2)
            .is_err(),
        "old issuer signed at the deactivation cutoff"
    );
    Ok(())
}

#[test]
fn kg2_retained_host_refuses_owned_clock_outage() -> TestResult {
    let fixture = Fixture::new()?;
    let authority = fixture.authority()?;
    fixture.clock.available.store(false, Ordering::SeqCst);
    assert!(
        authority.trusted_public_keys().is_empty(),
        "clock outage must not use cached keys"
    );
    assert!(authority
        .check_issuer_lifecycle(&fixture.old.public_key(), 1, 2)
        .is_err());
    Ok(())
}
