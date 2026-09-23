//! Witnessed parent authority for the actual confined provider invocation.
use super::*;
use chio_core_types::capability::token::CapabilityToken;
use chio_keyring::{
    BootstrapAuthorization, KeyLogAuthorizations, KeyLogEventBody, KeyLogOperation,
    KeyLogWitnessClient, KeyringSigningResult, SignedKeyLogEvent, SqliteKeyLogStore,
    SqlitePinnedKeyLogVerifier, SystemTrustedClock,
};
use chio_store_sqlite::SqliteReceiptStore;

#[path = "native_keyring_services.rs"]
mod services;
use services::{backend, KeyServices};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

pub(super) struct KeyringDelivery {
    pub parent: CapabilityToken,
    runtime: Option<chio_control_plane::KeyringRuntimeComposition>,
    evidence: KeyringSigningResult,
    policy: chio_keyring::KeyLogPolicy,
    verifier_path: PathBuf,
    _services: KeyServices,
    _receipt_anchors: tempfile::TempDir,
    config_path: PathBuf,
    seed_path: PathBuf,
    policy_document: chio_keyring::KeyLogPolicyDocument,
}

impl KeyringDelivery {
    pub fn new(directory: &Path, caller: &PublicKey) -> TestResult<Self> {
        let directory = fs::canonicalize(directory)?.join("keyring");
        fs::create_dir(&directory)?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        let document = services::policy_document();
        write_private(
            &directory.join("policy.json"),
            &canonical_json_bytes(&document)?,
        );
        let policy = chio_keyring::load_key_log_policy(directory.join("policy.json"))?;
        let mut services = KeyServices::witnesses(&directory, &policy)?;
        let store = Arc::new(SqliteKeyLogStore::open(
            directory.join("operator.sqlite3"),
            policy.clone(),
        )?);
        let active = Keypair::from_seed(&[232; 32]);
        let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
        let body = KeyLogEventBody {
            schema: chio_keyring::KEY_LOG_EVENT_SCHEMA.into(),
            log_id: chio_keyring::LogId::new(&document.log_id)?,
            sequence: 0,
            event_id: chio_keyring::EventId::new("event.native.genesis")?,
            previous_event_hash: None,
            authority_id: chio_keyring::AuthorityId::new(&document.authority_id)?,
            key_id: chio_keyring::derive_key_id(
                active.public_key().algorithm(),
                &active.public_key(),
            )?,
            algorithm: active.public_key().algorithm(),
            public_key: active.public_key(),
            operation: KeyLogOperation::Genesis,
            effective_at: now,
            verify_until: None,
            reason: None,
            issued_at: now,
        };
        let event = SignedKeyLogEvent {
            authorizations: KeyLogAuthorizations::bootstrap(BootstrapAuthorization::sign(
                &body,
                &backend(230),
            )?),
            body,
        };
        let checkpoint = store.append_event(&event, &backend(231))?;
        for witness in services.witnesses.iter().take(2) {
            let signature =
                witness.sign_candidate(&checkpoint, &store.synchronization_response(None)?)?;
            store.store_witness_signature(&checkpoint.checkpoint_hash()?, &signature)?;
        }
        drop(store);
        services.start_auditors(&directory)?;
        let seed_path = directory.join("authority.seed");
        write_private(&seed_path, hex::encode([232; 32]).as_bytes());
        write_private(&directory.join("operator.seed"), &[231; 32]);
        write_private(&directory.join("clock.seed"), &[233; 32]);
        let mut config = serde_json::to_value(&document)?;
        let object = config
            .as_object_mut()
            .ok_or("key-log policy is not an object")?;
        object.remove("max_checkpoint_future_skew_millis");
        object.remove("auditor_public_keys");
        object.extend(serde_json::from_value::<
            serde_json::Map<String, serde_json::Value>,
        >(serde_json::json!({
            "schema": "chio.keyring.runtime-config.v1",
            "database_path": directory.join("operator.sqlite3"),
            "enterprise_migration": services::migration_config(&directory, &policy)?,
            "operator_seed_file_path": directory.join("operator.seed"),
            "artifact_time_seed_file_path": directory.join("clock.seed"),
            "max_checkpoint_future_skew_seconds": 60,
            "audit_public_keys": document.auditor_public_keys,
            "witness_service_endpoints": services.witness_endpoints,
            "audit_service_endpoints": services.audit_endpoints,
        }))?);
        let config_path = directory.join("runtime.json");
        write_private(&config_path, &canonical_json_bytes(&config)?);
        let started = Instant::now();
        let runtime = loop {
            match chio_control_plane::load_keyring_runtime_composition(&active, &config_path) {
                Ok(runtime) => break runtime,
                Err(error) if started.elapsed() >= Duration::from_secs(10) => {
                    return Err(error.into())
                }
                Err(_) => thread::sleep(Duration::from_millis(20)),
            }
        };
        let readiness = runtime.startup_readiness()?;
        assert_eq!(readiness.durable_storage_identities.len(), 5);
        let receipt_anchors = tempfile::Builder::new()
            .prefix("chio-native-keyring-anchors-")
            .tempdir_in("/dev/shm")?;
        let receipts = Arc::new(SqliteReceiptStore::open_for_finding_pool(
            directory.join("key-receipts.sqlite3"),
            receipt_anchors.path(),
        )?);
        receipts.wait_for_writer_ready(Duration::from_secs(30))?;
        runtime.attach_receipt_store(receipts.clone())?;
        let issuer = runtime.capability_authority()?;
        let parent =
            issuer.issue_capability_with_aggregate_budget(caller, host::parent_scope(), 300, 1)?;
        let evidence = runtime.capability_signing_evidence(&parent)?;
        let verifier_path = directory.join("receiver.sqlite3");
        let verifier = SqlitePinnedKeyLogVerifier::provision(
            &verifier_path,
            policy.clone(),
            Arc::new(SystemTrustedClock),
        )?;
        let bytes = canonical_json_bytes(&parent.signing_body())?;
        let anchor = evidence
            .time_anchor
            .as_ref()
            .ok_or("parent issuance has no trusted time")?;
        assert!(verifier
            .verify_artifact_signing_evidence(&bytes, &evidence.evidence, anchor)
            .is_err());
        verifier.apply_sync(&runtime.key_log_synchronization_response(None)?)?;
        verifier.verify_artifact_signing_evidence(&bytes, &evidence.evidence, anchor)?;
        let base = verifier.pin()?.ok_or("receiver genesis pin absent")?;
        let (rotated, rotation) = runtime.rotate_remote_authority_seed(&seed_path)?;
        assert_ne!(rotated, parent.issuer);
        assert_eq!(rotation.signing_epoch, 1);
        let sync = runtime.key_log_synchronization_response(Some(&base))?;
        verifier.apply_sync(&sync)?;
        assert_eq!(verifier.pin()?, Some(rotation.audit_pin));
        verifier.verify_artifact_signing_evidence(&bytes, &evidence.evidence, anchor)?;
        let new_capability =
            issuer.issue_capability_with_aggregate_budget(caller, host::parent_scope(), 300, 1)?;
        assert_eq!(new_capability.issuer, rotated);
        let new_evidence = runtime.capability_signing_evidence(&new_capability)?;
        let new_anchor = new_evidence
            .time_anchor
            .as_ref()
            .ok_or("rotated issuance has no trusted time")?;
        verifier.verify_artifact_signing_evidence(
            &canonical_json_bytes(&new_capability.signing_body())?,
            &new_evidence.evidence,
            new_anchor,
        )?;
        assert!(verifier
            .verify_artifact_signing_evidence(&bytes, &evidence.evidence, new_anchor)
            .is_err());
        let mut forged = evidence.evidence.clone();
        forged.signing_epoch = 1;
        assert!(verifier
            .verify_artifact_signing_evidence(&bytes, &forged, anchor)
            .is_err());
        let mut missing = parent.clone();
        missing.id.push_str("-without-issuance-evidence");
        assert!(runtime.capability_signing_evidence(&missing).is_err());
        drop(issuer);
        drop(runtime);
        let stale = chio_control_plane::load_keyring_runtime_composition(&active, &config_path);
        let error = match stale {
            Ok(_) => return Err("retired authority seed reopened the issuer".into()),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("active backend does not match durable key selector"),
            "{error}"
        );
        let (recovered, runtime) =
            chio_control_plane::load_keyring_runtime_from_authority_seed(&config_path, &seed_path)?;
        assert_eq!(recovered.public_key(), rotated);
        runtime.attach_receipt_store(receipts)?;
        Ok(Self {
            parent,
            runtime: Some(runtime),
            evidence,
            policy,
            verifier_path,
            _services: services,
            _receipt_anchors: receipt_anchors,
            config_path,
            seed_path,
            policy_document: document,
        })
    }

    pub fn verify_parent(&self, original: &CapabilityToken) -> TestResult {
        assert_eq!(
            canonical_json_bytes(original)?,
            canonical_json_bytes(&self.parent)?
        );
        let retained = self
            .runtime
            .as_ref()
            .ok_or("key selector was handed to the process host")?
            .capability_signing_evidence(original)?;
        assert_eq!(retained, self.evidence);
        let verifier = SqlitePinnedKeyLogVerifier::open(
            &self.verifier_path,
            self.policy.clone(),
            Arc::new(SystemTrustedClock),
        )?;
        let key = verifier.verify_artifact_signing_evidence(
            &canonical_json_bytes(&original.signing_body())?,
            &retained.evidence,
            retained
                .time_anchor
                .as_ref()
                .ok_or("retained parent issuance has no trusted time")?,
        )?;
        assert_eq!(key.public_key, original.issuer);
        Ok(())
    }

    pub fn process_host_config(&self) -> serde_json::Value {
        serde_json::json!({
            "runtime_config": self.config_path,
            "authority_seed_file": self.seed_path,
            "receipt_anchor_directory": self._receipt_anchors.path(),
            "verification_policy": self.policy_document,
        })
    }

    pub fn into_process_host(mut self) -> Self {
        // The real CLI must acquire sole selector custody after provisioning.
        // Keep independent witnesses, auditors and public verifier state alive.
        self.runtime.take();
        self
    }

    pub fn rotate_process_host_authority(&self, original: &CapabilityToken) -> TestResult {
        assert!(self.runtime.is_none(), "the host must own the selector");
        let (_, runtime) = chio_control_plane::load_keyring_runtime_from_authority_seed(
            &self.config_path,
            &self.seed_path,
        )?;
        let receipts = Arc::new(SqliteReceiptStore::open_for_finding_pool(
            self.config_path.with_file_name("key-receipts.sqlite3"),
            self._receipt_anchors.path(),
        )?);
        receipts.wait_for_writer_ready(Duration::from_secs(30))?;
        runtime.attach_receipt_store(receipts)?;
        let (rotated, _) = runtime.rotate_remote_authority_seed(&self.seed_path)?;
        assert_ne!(rotated, original.issuer);
        let verifier = SqlitePinnedKeyLogVerifier::open(
            &self.verifier_path,
            self.policy.clone(),
            Arc::new(SystemTrustedClock),
        )?;
        let base = verifier.pin()?.ok_or("independent receiver pin")?;
        verifier.apply_sync(&runtime.key_log_synchronization_response(Some(&base))?)?;
        let evidence = runtime.capability_signing_evidence(original)?;
        let key = verifier.verify_artifact_signing_evidence(
            &canonical_json_bytes(&original.signing_body())?,
            &evidence.evidence,
            evidence
                .time_anchor
                .as_ref()
                .ok_or("original issuance time")?,
        )?;
        assert_eq!(key.public_key, original.issuer);
        Ok(())
    }

    pub fn verifier_path(&self) -> &Path {
        &self.verifier_path
    }
}
