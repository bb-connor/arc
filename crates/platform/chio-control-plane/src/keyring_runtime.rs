//! Production composition for witnessed authority-key transparency.

use std::collections::BTreeMap;
#[cfg(not(unix))]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use chio_core::crypto::{Keypair, SigningBackend};
use chio_security_types::ports::{Digest32, RecordId};
use chio_security_types::{
    EnterpriseMigrationControl, EnterpriseMigrationKey, EnterpriseMigrationMinimumHead,
    EnterpriseMigrationRuntimeBinding, EnterpriseMigrationScopeKind, EnterpriseMigrationStage,
    EnterpriseMigrationStateStore,
};
use chio_store_sqlite::{SqliteEnterpriseMigrationOpenPolicy, SqliteEnterpriseMigrationStateStore};

use crate::CliError;

#[derive(Clone)]
pub struct KeyringRuntimeComposition {
    router: Arc<chio_keyring::KeyringSigningRouter>,
    store: Arc<chio_keyring::SqliteKeyLogStore>,
    independent_services: Arc<chio_keyring::IndependentKeyLogServices>,
    rotation_runtime: Arc<chio_keyring::WitnessedRotationRuntime>,
    startup_readiness: chio_keyring::IndependentOperationReadiness,
    migration_binding: KeyLogMigrationBinding,
    authority_backend: Arc<MigrationGuardedSigningBackend>,
    operator_backend: Arc<dyn SigningBackend>,
    receipt_store: Arc<Mutex<Option<AttachedReceiptStore>>>,
    authority_rotation_lock: Arc<Mutex<()>>,
}

#[derive(Clone)]
struct MigrationGuardedSigningBackend {
    inner: Arc<dyn SigningBackend>,
    migration_binding: KeyLogMigrationBinding,
}

impl MigrationGuardedSigningBackend {
    fn require_enforced(&self) -> chio_core::error::Result<()> {
        self.migration_binding.require_enforced().map_err(|error| {
            chio_core::error::Error::InvalidSignature(format!(
                "key-log verification migration denied keyring signing: {error}"
            ))
        })
    }
}

impl SigningBackend for MigrationGuardedSigningBackend {
    fn algorithm(&self) -> chio_core::SigningAlgorithm {
        self.inner.algorithm()
    }

    fn public_key(&self) -> chio_core::PublicKey {
        self.inner.public_key()
    }

    fn sign_bytes(&self, message: &[u8]) -> chio_core::error::Result<chio_core::Signature> {
        self.require_enforced()?;
        let signature = self.inner.sign_bytes(message)?;
        self.require_enforced()?;
        Ok(signature)
    }

    fn sign_bytes_with_identity(
        &self,
        message: &[u8],
    ) -> chio_core::error::Result<chio_core::crypto::SigningOutcome> {
        self.require_enforced()?;
        let outcome = self.inner.sign_bytes_with_identity(message)?;
        self.require_enforced()?;
        Ok(outcome)
    }

    fn sign_bytes_for_identity(
        &self,
        expected_key: &chio_core::PublicKey,
        message: &[u8],
    ) -> chio_core::error::Result<chio_core::crypto::SigningOutcome> {
        self.require_enforced()?;
        let outcome = self.inner.sign_bytes_for_identity(expected_key, message)?;
        self.require_enforced()?;
        Ok(outcome)
    }

    fn sign_canonical_bytes(
        &self,
        canonical: &chio_core::canonical::CanonicalBytes<
            chio_core::canonical::CanonicalJsonWitness,
        >,
    ) -> chio_core::error::Result<chio_core::Signature> {
        self.require_enforced()?;
        let signature = self.inner.sign_canonical_bytes(canonical)?;
        self.require_enforced()?;
        Ok(signature)
    }
}

#[derive(Clone)]
struct KeyLogMigrationBinding(EnterpriseMigrationRuntimeBinding);

impl KeyLogMigrationBinding {
    fn require_enforced(&self) -> Result<(), chio_security_types::EnterpriseMigrationRuntimeError> {
        self.0.require_enforced()
    }
}

impl chio_keyring::KeyLogActivationGuard for KeyLogMigrationBinding {
    fn require_activation(&self) -> chio_keyring::Result<()> {
        self.require_enforced().map_err(|_| {
            chio_keyring::KeyringError::StateInvariant(
                "key-log verification migration denied selector activation",
            )
        })
    }
}

#[derive(Clone, Debug)]
pub struct KeyringRuntimeAuthorityStatus {
    pub public_key: chio_core::PublicKey,
    pub signing_epoch: u64,
    pub activated_at: Option<u64>,
    pub witnessed_verification_keys: Vec<chio_core::PublicKey>,
    pub operator_head: Option<chio_keyring::KeyLogPin>,
    pub checkpoint_stage: Option<chio_keyring::CheckpointStage>,
    pub witness_service_count: usize,
    pub audit_service_count: usize,
}

#[derive(Clone)]
struct AttachedReceiptStore {
    identity: String,
    store: Arc<dyn chio_kernel::ReceiptStore>,
}

fn attach_receipt_store_transactionally<F>(
    attachment: &Mutex<Option<AttachedReceiptStore>>,
    candidate: Arc<dyn chio_kernel::ReceiptStore>,
    backfill: F,
) -> Result<usize, CliError>
where
    F: FnOnce(&dyn chio_kernel::ReceiptStore) -> Result<usize, CliError>,
{
    let identity = candidate
        .durable_sink_id()
        .map(str::to_owned)
        .ok_or_else(|| {
            CliError::cli_other_error(
                "keyring receipt store must expose a durable commit-domain identity".to_string(),
            )
        })?;
    let mut configured = attachment.lock().map_err(|_| {
        CliError::cli_other_error(
            "keyring receipt-store attachment lock is unavailable".to_string(),
        )
    })?;
    if let Some(existing) = configured.as_ref() {
        if existing.identity != identity {
            return Err(CliError::cli_other_error(
                "keyring receipt store is already bound to a different durable commit domain"
                    .to_string(),
            ));
        }
        return backfill(existing.store.as_ref());
    }

    let appended = backfill(candidate.as_ref())?;
    *configured = Some(AttachedReceiptStore {
        identity,
        store: candidate,
    });
    Ok(appended)
}

impl KeyringRuntimeComposition {
    fn require_key_log_verification(&self) -> Result<(), CliError> {
        self.migration_binding.require_enforced().map_err(|error| {
            CliError::cli_other_error(format!(
                "key-log verification migration enforcement failed: {error}"
            ))
        })
    }

    pub(crate) fn ensure_bound_signing_topology(&self) -> Result<(), CliError> {
        self.require_key_log_verification()?;
        if !self.router.uses_store(&self.store) {
            return Err(CliError::cli_other_error(
                "keyring signing router and artifact trust resolver must share one durable store"
                    .to_string(),
            ));
        }
        Ok(())
    }

    pub(crate) fn key_log_synchronization_response(
        &self,
        base: Option<&chio_keyring::KeyLogPin>,
    ) -> Result<chio_keyring::KeyLogSyncResponse, CliError> {
        self.require_key_log_verification()?;
        self.store
            .synchronization_response(base)
            .map_err(|error| CliError::cli_other_error(error.to_string()))
    }

    #[must_use]
    pub(crate) fn authority_signing_backend(&self) -> Arc<dyn SigningBackend> {
        self.authority_backend.clone()
    }

    pub fn authority_status(&self) -> Result<KeyringRuntimeAuthorityStatus, CliError> {
        self.require_key_log_verification()?;
        let public_key = self
            .router
            .active_public_key()
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        let signing_epoch = self
            .router
            .signing_epoch()
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        let state = self
            .store
            .load_state()
            .map_err(|error| CliError::cli_other_error(error.to_string()))?
            .ok_or_else(|| {
                CliError::cli_other_error(
                    "keyring authority status requires a witnessed key-log state".to_string(),
                )
            })?;
        let active = state
            .active_signing_key()
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        if active.public_key != public_key || state.signing_epoch() != signing_epoch {
            return Err(CliError::cli_other_error(
                "keyring selector does not match the witnessed key-log state".to_string(),
            ));
        }
        let witnessed_verification_keys = state
            .witnessed_verification_keys()
            .into_iter()
            .map(|record| record.public_key)
            .collect();
        Ok(KeyringRuntimeAuthorityStatus {
            public_key,
            signing_epoch,
            activated_at: (active.activated_at != 0).then_some(active.activated_at),
            witnessed_verification_keys,
            operator_head: self
                .store
                .head_pin()
                .map_err(|error| CliError::cli_other_error(error.to_string()))?,
            checkpoint_stage: self
                .store
                .head_stage()
                .map_err(|error| CliError::cli_other_error(error.to_string()))?,
            witness_service_count: self.independent_services.witnesses().len(),
            audit_service_count: self.independent_services.auditors().len(),
        })
    }

    pub fn startup_readiness(
        &self,
    ) -> Result<&chio_keyring::IndependentOperationReadiness, CliError> {
        self.require_key_log_verification()?;
        Ok(&self.startup_readiness)
    }

    pub fn attach_receipt_store(
        &self,
        receipt_store: Arc<dyn chio_kernel::ReceiptStore>,
    ) -> Result<usize, CliError> {
        self.require_key_log_verification()?;
        attach_receipt_store_transactionally(
            self.receipt_store.as_ref(),
            receipt_store,
            |retained| self.forward_enterprise_receipts(retained),
        )
    }

    pub fn forward_enterprise_receipts(
        &self,
        receipt_store: &dyn chio_kernel::ReceiptStore,
    ) -> Result<usize, CliError> {
        self.require_key_log_verification()?;
        let configuration_binding = self
            .store
            .configuration_binding()
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        let mut appended = 0;
        for enterprise_receipt in self
            .store
            .load_enterprise_receipts()
            .map_err(|error| CliError::cli_other_error(error.to_string()))?
        {
            self.require_key_log_verification()?;
            if persist_key_enterprise_receipt(
                &enterprise_receipt,
                self.operator_backend.as_ref(),
                configuration_binding,
                receipt_store,
                &self.migration_binding,
            )? {
                appended += 1;
            }
        }
        Ok(appended)
    }

    pub(crate) fn rotate_or_resume_authority(
        &self,
        new_keypair: &Keypair,
    ) -> Result<chio_keyring::WitnessedRotationOutcome, CliError> {
        self.require_key_log_verification()?;
        let new_inner: Arc<dyn SigningBackend> =
            Arc::new(chio_core::crypto::Ed25519Backend::new(new_keypair.clone()));
        let new_backend = MigrationGuardedSigningBackend {
            inner: new_inner,
            migration_binding: self.migration_binding.clone(),
        };
        let state = self
            .store
            .load_state()
            .map_err(|error| CliError::cli_other_error(error.to_string()))?
            .ok_or_else(|| {
                CliError::cli_other_error("keyring operator log is not initialized".to_string())
            })?;
        let mut pending = if state.pending_event_id().is_some() {
            self.require_key_log_verification()?;
            self.rotation_runtime
                .resume_pending_rotation(Box::new(new_backend.clone()))
                .map_err(|error| CliError::cli_other_error(error.to_string()))?
        } else {
            let previous = self
                .store
                .load_events()
                .map_err(|error| CliError::cli_other_error(error.to_string()))?
                .into_iter()
                .last()
                .ok_or_else(|| {
                    CliError::cli_other_error(
                        "keyring operator log has no authority event".to_string(),
                    )
                })?;
            let policy = self.store.policy_clone();
            let issued_at = u64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| {
                        CliError::cli_other_error("system time precedes the Unix epoch".to_string())
                    })?
                    .as_millis(),
            )
            .map_err(|_| {
                CliError::cli_other_error("system time exceeds key-log range".to_string())
            })?;
            let sequence = previous.body.sequence.checked_add(1).ok_or_else(|| {
                CliError::cli_other_error("key-log sequence overflow".to_string())
            })?;
            let new_public_key = new_backend.public_key();
            let body = chio_keyring::KeyLogEventBody {
                schema: chio_keyring::KEY_LOG_EVENT_SCHEMA.to_string(),
                log_id: policy.log_id().clone(),
                sequence,
                event_id: chio_keyring::EventId::new(format!(
                    "event.authority.rotation.{sequence}"
                ))
                .map_err(|error| CliError::cli_other_error(error.to_string()))?,
                previous_event_hash: Some(
                    previous
                        .envelope_hash()
                        .map_err(|error| CliError::cli_other_error(error.to_string()))?,
                ),
                authority_id: policy.authority_id().clone(),
                key_id: chio_keyring::derive_key_id(new_backend.algorithm(), &new_public_key)
                    .map_err(|error| CliError::cli_other_error(error.to_string()))?,
                algorithm: new_backend.algorithm(),
                public_key: new_public_key,
                operation: chio_keyring::KeyLogOperation::Rotate {
                    previous_key_id: state
                        .active_signing_key()
                        .map_err(|error| CliError::cli_other_error(error.to_string()))?
                        .key_id,
                    witness_roster_id: policy.witness_roster_id().clone(),
                    witness_roster_binding: policy
                        .witness_roster_binding()
                        .map_err(|error| CliError::cli_other_error(error.to_string()))?,
                },
                effective_at: issued_at,
                verify_until: Some(issued_at.checked_add(86_400_000).ok_or_else(|| {
                    CliError::cli_other_error("key rotation validity overflow".to_string())
                })?),
                reason: Some(
                    chio_keyring::EventReason::new("remote authority admin rotation")
                        .map_err(|error| CliError::cli_other_error(error.to_string()))?,
                ),
                issued_at,
            };
            let event = chio_keyring::SignedKeyLogEvent {
                authorizations: chio_keyring::KeyLogAuthorizations::rotation(
                    chio_keyring::OldKeyAuthorization::sign(&body, self.authority_backend.as_ref())
                        .map_err(|error| CliError::cli_other_error(error.to_string()))?,
                    chio_keyring::NewKeyProofOfPossession::sign(&body, &new_backend)
                        .map_err(|error| CliError::cli_other_error(error.to_string()))?,
                ),
                body,
            };
            self.require_key_log_verification()?;
            self.rotation_runtime
                .begin_rotation(&event, Box::new(new_backend))
                .map_err(|error| CliError::cli_other_error(error.to_string()))?
        };
        self.require_key_log_verification()?;
        self.rotation_runtime
            .collect_witnesses_and_activate(&mut pending, &self.independent_services)
            .map_err(|error| CliError::cli_other_error(error.to_string()))
    }

    pub fn rotate_remote_authority_seed(
        &self,
        active_seed_path: &Path,
    ) -> Result<(chio_core::PublicKey, chio_keyring::WitnessedRotationOutcome), CliError> {
        self.require_key_log_verification()?;
        let _rotation = self.authority_rotation_lock.lock().map_err(|_| {
            CliError::cli_other_error("keyring authority rotation lock is unavailable".to_string())
        })?;
        let (active_keypair, active_identity) =
            load_existing_authority_keypair_with_identity(active_seed_path)?;
        let state = self
            .store
            .load_state()
            .map_err(|error| CliError::cli_other_error(error.to_string()))?
            .ok_or_else(|| {
                CliError::cli_other_error("keyring operator log is not initialized".to_string())
            })?;
        let active_record = state
            .active_signing_key()
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        let active_key_id = chio_keyring::derive_key_id(
            active_keypair.public_key().algorithm(),
            &active_keypair.public_key(),
        )
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        let pending_path = keyring_pending_authority_seed_path(active_seed_path);
        let pending = load_optional_authority_seed_handoff(&pending_path)?;
        if active_key_id != active_record.key_id {
            let Some((handoff, recovered, pending_identity)) = pending else {
                return Err(CliError::cli_other_error(
                    "authority seed identity does not match the durable active selector"
                        .to_string(),
                ));
            };
            handoff.validate_keypair(&recovered)?;
            if state.pending_event_id().is_some()
                || handoff.target_epoch != state.signing_epoch()
                || handoff.key_id != active_record.key_id.to_string()
            {
                return Err(CliError::cli_other_error(
                    "authority seed recovery is not bound to the active selector epoch".to_string(),
                ));
            }
            self.require_key_log_verification()?;
            write_authority_seed_file_bound(active_seed_path, &recovered, Some(&active_identity))?;
            self.require_key_log_verification()?;
            remove_authority_seed_handoff(&pending_path, &handoff, &pending_identity)?;
            return Ok((recovered.public_key(), self.current_rotation_outcome()?));
        }
        let (next_keypair, pending_identity, target_epoch) = match pending {
            Some((handoff, keypair, identity)) => {
                handoff.validate_keypair(&keypair)?;
                if state.pending_event_id().is_none() {
                    match classify_quiescent_authority_seed_handoff(
                        &handoff,
                        state.signing_epoch(),
                        &active_record.key_id.to_string(),
                    )? {
                        QuiescentAuthoritySeedHandoff::Completed => {
                            self.require_key_log_verification()?;
                            remove_authority_seed_handoff(&pending_path, &handoff, &identity)?;
                            return Ok((
                                active_keypair.public_key(),
                                self.current_rotation_outcome()?,
                            ));
                        }
                        QuiescentAuthoritySeedHandoff::Resumable { target_epoch } => {
                            (keypair, identity, target_epoch)
                        }
                    }
                } else {
                    let pending_record = state.pending_rotation_key().ok_or_else(|| {
                        CliError::cli_other_error(
                            "durable pending event is missing its pending key".to_string(),
                        )
                    })?;
                    let expected_target =
                        state.signing_epoch().checked_add(1).ok_or_else(|| {
                            CliError::cli_other_error(
                                "authority signing epoch overflow".to_string(),
                            )
                        })?;
                    if handoff.base_epoch != state.signing_epoch()
                        || handoff.target_epoch != expected_target
                        || handoff.key_id != pending_record.key_id.to_string()
                    {
                        return Err(CliError::cli_other_error(
                            "pending authority seed does not match the durable rotation"
                                .to_string(),
                        ));
                    }
                    (keypair, identity, expected_target)
                }
            }
            None => {
                if state.pending_event_id().is_some() {
                    return Err(CliError::cli_other_error(
                        "durable pending rotation is missing its bound seed handoff".to_string(),
                    ));
                }
                let keypair = Keypair::generate();
                let target_epoch = state.signing_epoch().checked_add(1).ok_or_else(|| {
                    CliError::cli_other_error("authority signing epoch overflow".to_string())
                })?;
                let handoff =
                    AuthoritySeedHandoff::new(&keypair, state.signing_epoch(), target_epoch)?;
                self.require_key_log_verification()?;
                let identity = persist_authority_seed_handoff(&pending_path, &handoff)?;
                (keypair, identity, target_epoch)
            }
        };
        let outcome = self.rotate_or_resume_authority(&next_keypair)?;
        let next_key_id = chio_keyring::derive_key_id(
            next_keypair.public_key().algorithm(),
            &next_keypair.public_key(),
        )
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        self.require_key_log_verification()?;
        if outcome.signing_epoch != target_epoch
            || self
                .router
                .active_public_key()
                .map_err(|error| CliError::cli_other_error(error.to_string()))?
                != next_keypair.public_key()
        {
            return Err(CliError::cli_other_error(
                "activated authority selector does not match the seed handoff".to_string(),
            ));
        }
        let handoff = load_authority_seed_handoff(&pending_path)?.0;
        if handoff.key_id != next_key_id.to_string() || handoff.target_epoch != target_epoch {
            return Err(CliError::cli_other_error(
                "authority seed handoff changed during activation".to_string(),
            ));
        }
        self.require_key_log_verification()?;
        write_authority_seed_file_bound(active_seed_path, &next_keypair, Some(&active_identity))?;
        self.require_key_log_verification()?;
        remove_authority_seed_handoff(&pending_path, &handoff, &pending_identity)?;
        Ok((next_keypair.public_key(), outcome))
    }

    fn current_rotation_outcome(&self) -> Result<chio_keyring::WitnessedRotationOutcome, CliError> {
        self.require_key_log_verification()?;
        let audit_pin = self
            .store
            .head_pin()
            .map_err(|error| CliError::cli_other_error(error.to_string()))?
            .ok_or_else(|| CliError::cli_other_error("key log has no active head".to_string()))?;
        Ok(chio_keyring::WitnessedRotationOutcome {
            checkpoint_hash: audit_pin.checkpoint_hash,
            signing_epoch: audit_pin.signing_epoch,
            audit_pin,
        })
    }
}

struct ControlPlaneKeyEnterpriseReceiptSink {
    operator_backend: Arc<dyn SigningBackend>,
    configuration_binding: chio_core::Hash,
    receipt_store: Arc<Mutex<Option<AttachedReceiptStore>>>,
    migration_binding: KeyLogMigrationBinding,
}

impl chio_keyring::KeyEnterpriseReceiptSink for ControlPlaneKeyEnterpriseReceiptSink {
    fn persist(
        &self,
        receipt: &chio_keyring::SignedKeyEnterpriseReceipt,
    ) -> chio_keyring::Result<()> {
        self.migration_binding.require_enforced().map_err(|_| {
            chio_keyring::KeyringError::StateInvariant(
                "key-log verification migration denied enterprise receipt persistence",
            )
        })?;
        let receipt_store = self
            .receipt_store
            .lock()
            .map_err(|_| chio_keyring::KeyringError::Synchronization)?
            .clone()
            .ok_or(chio_keyring::KeyringError::StateInvariant(
                "production key rotation requires an attached normal receipt store",
            ))?;
        self.migration_binding.require_enforced().map_err(|_| {
            chio_keyring::KeyringError::StateInvariant(
                "key-log verification migration denied enterprise receipt verification",
            )
        })?;
        persist_key_enterprise_receipt(
            receipt,
            self.operator_backend.as_ref(),
            self.configuration_binding,
            receipt_store.store.as_ref(),
            &self.migration_binding,
        )
        .map(|_| ())
        .map_err(|error| chio_keyring::KeyringError::Storage(error.to_string()))
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyringRuntimeConfig {
    schema: String,
    database_path: PathBuf,
    enterprise_migration: KeyLogVerificationMigrationConfig,
    log_id: String,
    authority_id: String,
    bootstrap_public_key: String,
    operator_public_key: String,
    operator_seed_file_path: PathBuf,
    witness_roster_id: String,
    witness_public_keys: BTreeMap<String, String>,
    witness_service_endpoints: BTreeMap<String, PathBuf>,
    audit_service_endpoints: BTreeMap<String, PathBuf>,
    audit_public_keys: BTreeMap<String, String>,
    recovery_policy_id: String,
    #[serde(default)]
    recovery_public_keys: BTreeMap<String, String>,
    recovery_threshold: usize,
    artifact_time_public_keys: BTreeMap<String, String>,
    artifact_time_seed_file_path: PathBuf,
    max_checkpoint_future_skew_seconds: u64,
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyLogVerificationMigrationConfig {
    state_database_path: PathBuf,
    deployment_id: RecordId,
    stage: EnterpriseMigrationStage,
    trusted_transition_signers: Vec<chio_core::PublicKey>,
    minimum_heads: Vec<EnterpriseMigrationMinimumHead>,
}

impl KeyLogVerificationMigrationConfig {
    fn validated_key(&self) -> Result<EnterpriseMigrationKey, CliError> {
        if !self.stage.operational_failure_must_deny() {
            return Err(CliError::cli_other_error(
                "production key-log verification migration must be enforced".to_string(),
            ));
        }
        if self.trusted_transition_signers.is_empty()
            || self.trusted_transition_signers.len() > 16
            || self
                .trusted_transition_signers
                .windows(2)
                .any(|pair| pair[0].to_hex() >= pair[1].to_hex())
        {
            return Err(CliError::cli_other_error(
                "key-log migration transition signers must be nonempty, bounded, sorted, and unique"
                    .to_string(),
            ));
        }
        let key = EnterpriseMigrationKey {
            deployment_id: self.deployment_id.clone(),
            scope_kind: EnterpriseMigrationScopeKind::Deployment,
            scope_id: self.deployment_id.clone(),
            control: EnterpriseMigrationControl::KeyLogVerification,
        };
        if self.minimum_heads.len() != 1
            || self.minimum_heads[0].key != key
            || !self.minimum_heads[0].is_valid()
            || self.minimum_heads[0].minimum_generation != self.stage.generation()
        {
            return Err(CliError::cli_other_error(
                "key-log migration requires one exact externally anchored deployment head"
                    .to_string(),
            ));
        }
        Ok(key)
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KeyLogVerificationMigrationPosture<'a> {
    schema: &'static str,
    deployment_id: &'a RecordId,
    control: EnterpriseMigrationControl,
    stage: EnterpriseMigrationStage,
    key_log_configuration_binding: chio_core::Hash,
}

fn key_log_verification_migration_posture_digest(
    config: &KeyLogVerificationMigrationConfig,
    key_log_configuration_binding: chio_core::Hash,
) -> Result<Digest32, CliError> {
    let canonical = chio_core::canonical_json_bytes(&KeyLogVerificationMigrationPosture {
        schema: "chio.key-log-verification-migration-posture.v1",
        deployment_id: &config.deployment_id,
        control: EnterpriseMigrationControl::KeyLogVerification,
        stage: config.stage,
        key_log_configuration_binding,
    })?;
    Ok(Digest32::new(
        *chio_core::hashing::sha256(&canonical).as_bytes(),
    ))
}

fn require_distinct_key_log_and_migration_databases(
    key_log_database_path: &Path,
    migration_database_path: &Path,
) -> Result<(), CliError> {
    let key_log_path = fs::canonicalize(key_log_database_path)?;
    let migration_path = fs::canonicalize(migration_database_path)?;
    if key_log_path == migration_path {
        return Err(CliError::cli_other_error(
            "key log and enterprise migration ledger require distinct durable files".to_string(),
        ));
    }
    #[cfg(unix)]
    {
        let key_log_metadata = fs::metadata(&key_log_path)?;
        let migration_metadata = fs::metadata(&migration_path)?;
        if key_log_metadata.dev() == migration_metadata.dev()
            && key_log_metadata.ino() == migration_metadata.ino()
        {
            return Err(CliError::cli_other_error(
                "key log and enterprise migration ledger cannot share one inode".to_string(),
            ));
        }
    }
    Ok(())
}

fn load_key_log_verification_migration_binding(
    config: &KeyLogVerificationMigrationConfig,
    key_log_policy: &chio_keyring::KeyLogPolicy,
    key_log_database_path: &Path,
) -> Result<KeyLogMigrationBinding, CliError> {
    let key = config.validated_key()?;
    require_distinct_key_log_and_migration_databases(
        key_log_database_path,
        &config.state_database_path,
    )?;
    let posture_digest = key_log_verification_migration_posture_digest(
        config,
        key_log_policy
            .configuration_binding()
            .map_err(|error| CliError::cli_other_error(error.to_string()))?,
    )?;
    let policy = SqliteEnterpriseMigrationOpenPolicy::new(
        config.trusted_transition_signers.clone(),
        config.minimum_heads.clone(),
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("key-log migration open policy failed: {error}"))
    })?;
    let concrete = Arc::new(
        SqliteEnterpriseMigrationStateStore::open(&config.state_database_path, policy).map_err(
            |error| {
                CliError::cli_other_error(format!(
                    "key-log migration state database failed: {error}"
                ))
            },
        )?,
    );
    let store: Arc<dyn EnterpriseMigrationStateStore> = concrete;
    let binding =
        EnterpriseMigrationRuntimeBinding::load(&store, &key, config.stage, posture_digest)
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "key-log verification migration binding failed: {error}"
                ))
            })?;
    binding.require_enforced().map_err(|error| {
        CliError::cli_other_error(format!(
            "key-log verification migration is not enforced: {error}"
        ))
    })?;
    Ok(KeyLogMigrationBinding(binding))
}

pub fn load_keyring_runtime_composition(
    kernel_kp: &Keypair,
    config_path: &Path,
) -> Result<KeyringRuntimeComposition, CliError> {
    let config_bytes = fs::read(config_path)?;
    let config: KeyringRuntimeConfig = serde_yml::from_slice(&config_bytes)?;
    if config.schema != "chio.keyring.runtime-config.v1" {
        return Err(CliError::cli_other_error(
            "unsupported keyring runtime configuration schema".to_string(),
        ));
    }
    if config.witness_public_keys.len() != 3
        || config.witness_service_endpoints.len() != 3
        || config.audit_service_endpoints.len() != 2
        || config.audit_public_keys.len() != 2
        || config
            .audit_service_endpoints
            .keys()
            .collect::<std::collections::BTreeSet<_>>()
            != config
                .audit_public_keys
                .keys()
                .collect::<std::collections::BTreeSet<_>>()
        || config.artifact_time_public_keys.is_empty()
    {
        return Err(CliError::cli_other_error(
            "keyring production configuration requires three witnesses, two auditors, and artifact-time trust roots"
                .to_string(),
        ));
    }
    let witnesses = parse_keyring_public_keys(config.witness_public_keys, |value| {
        chio_keyring::WitnessId::new(value)
    })?;
    let recovery = parse_keyring_public_keys(config.recovery_public_keys, |value| {
        chio_keyring::RecoveryAuthorizerId::new(value)
    })?;
    let artifact_time = parse_keyring_public_keys(config.artifact_time_public_keys, |value| {
        chio_keyring::AnchorId::new(value)
    })?;
    let artifact_time_inner: Arc<dyn SigningBackend> = Arc::new(load_private_seed_backend(
        &config.artifact_time_seed_file_path,
    )?);
    let artifact_time_anchor_id = artifact_time
        .iter()
        .find_map(|(anchor_id, public_key)| {
            (public_key == &artifact_time_inner.public_key()).then(|| anchor_id.clone())
        })
        .ok_or_else(|| {
            CliError::cli_other_error(
                "artifact-time signing seed does not match a configured trust root".to_string(),
            )
        })?;
    let audit_public_keys = config
        .audit_public_keys
        .into_iter()
        .map(|(identifier, key)| Ok((identifier, parse_keyring_public_key(&key)?)))
        .collect::<Result<BTreeMap<_, _>, CliError>>()?;
    let key_log_policy = chio_keyring::KeyLogPolicy::new(chio_keyring::KeyLogPolicyConfig {
        log_id: chio_keyring::LogId::new(config.log_id)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?,
        authority_id: chio_keyring::AuthorityId::new(config.authority_id)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?,
        bootstrap_key: parse_keyring_public_key(&config.bootstrap_public_key)?,
        operator_key: parse_keyring_public_key(&config.operator_public_key)?,
        witness_roster_id: chio_keyring::WitnessRosterId::new(config.witness_roster_id)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?,
        witness_keys: witnesses,
        recovery_policy_id: chio_keyring::RecoveryPolicyId::new(config.recovery_policy_id)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?,
        recovery_keys: recovery,
        recovery_threshold: config.recovery_threshold,
        max_checkpoint_future_skew: checkpoint_future_skew_millis(
            config.max_checkpoint_future_skew_seconds,
        )?,
    })
    .and_then(|policy| policy.with_artifact_time_roots(artifact_time))
    .and_then(|policy| policy.with_auditor_roots(audit_public_keys))
    .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let migration_binding = load_key_log_verification_migration_binding(
        &config.enterprise_migration,
        &key_log_policy,
        &config.database_path,
    )?;
    let artifact_time_backend: Arc<dyn SigningBackend> = Arc::new(MigrationGuardedSigningBackend {
        inner: artifact_time_inner,
        migration_binding: migration_binding.clone(),
    });
    let witness_service_endpoints = config
        .witness_service_endpoints
        .into_iter()
        .map(|(identifier, endpoint)| {
            Ok((
                chio_keyring::WitnessId::new(identifier)
                    .map_err(|error| CliError::cli_other_error(error.to_string()))?,
                endpoint,
            ))
        })
        .collect::<Result<BTreeMap<_, _>, CliError>>()?;
    let store = Arc::new(
        chio_keyring::SqliteKeyLogStore::open_existing(
            &config.database_path,
            key_log_policy.clone(),
        )
        .map_err(|error| CliError::cli_other_error(error.to_string()))?,
    );
    let operator_head = store
        .head_pin()
        .map_err(|error| CliError::cli_other_error(error.to_string()))?
        .ok_or_else(|| {
            CliError::cli_other_error(
                "keyring operator log must be initialized before runtime startup".to_string(),
            )
        })?;
    let accepted_pin = match store
        .head_stage()
        .map_err(|error| CliError::cli_other_error(error.to_string()))?
    {
        Some(chio_keyring::CheckpointStage::Witnessed)
        | Some(chio_keyring::CheckpointStage::Activated) => operator_head.clone(),
        Some(chio_keyring::CheckpointStage::Pending) => store
            .latest_accepted_pin()
            .map_err(|error| CliError::cli_other_error(error.to_string()))?
            .ok_or_else(|| {
                CliError::cli_other_error(
                    "keyring cannot boot from a pending genesis checkpoint".to_string(),
                )
            })?,
        None => {
            return Err(CliError::cli_other_error(
                "keyring operator log has no durable checkpoint".to_string(),
            ));
        }
    };
    let (independent_services, startup_readiness) =
        chio_keyring::IndependentKeyLogServices::connect_and_validate(
            &key_log_policy,
            witness_service_endpoints,
            config.audit_service_endpoints,
            &accepted_pin,
            &operator_head,
        )
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let operator_storage_identity = store.storage_identity();
    if startup_readiness
        .durable_storage_identities
        .contains(&operator_storage_identity)
    {
        return Err(CliError::cli_other_error(
            "operator, witnesses, and auditors must use independently durable storage".to_string(),
        ));
    }
    let operator_inner: Arc<dyn SigningBackend> =
        Arc::new(load_private_seed_backend(&config.operator_seed_file_path)?);
    let operator_backend: Arc<dyn SigningBackend> = Arc::new(MigrationGuardedSigningBackend {
        inner: operator_inner,
        migration_binding: migration_binding.clone(),
    });
    let active_inner: Arc<dyn SigningBackend> =
        Arc::new(chio_core::crypto::Ed25519Backend::new(kernel_kp.clone()));
    let active_backend: Box<dyn SigningBackend> = Box::new(MigrationGuardedSigningBackend {
        inner: active_inner,
        migration_binding: migration_binding.clone(),
    });
    let router = Arc::new(
        chio_keyring::KeyringSigningRouter::open_enterprise(
            Arc::clone(&store),
            active_backend,
            artifact_time_anchor_id,
            artifact_time_backend,
        )
        .map_err(|error| CliError::cli_other_error(error.to_string()))?,
    );
    let independent_services = Arc::new(independent_services);
    let keyring_authority_backend = Arc::new(
        chio_keyring::KeyringAuthoritySigningBackend::new_enterprise(
            Arc::clone(&router),
            Arc::clone(&independent_services),
        )
        .map_err(|error| CliError::cli_other_error(error.to_string()))?,
    );
    let guarded_inner: Arc<dyn SigningBackend> = keyring_authority_backend;
    let authority_backend = Arc::new(MigrationGuardedSigningBackend {
        inner: guarded_inner,
        migration_binding: migration_binding.clone(),
    });
    let receipt_store = Arc::new(Mutex::new(None));
    let receipt_sink: Arc<dyn chio_keyring::KeyEnterpriseReceiptSink> =
        Arc::new(ControlPlaneKeyEnterpriseReceiptSink {
            operator_backend: Arc::clone(&operator_backend),
            configuration_binding: key_log_policy
                .configuration_binding()
                .map_err(|error| CliError::cli_other_error(error.to_string()))?,
            receipt_store: Arc::clone(&receipt_store),
            migration_binding: migration_binding.clone(),
        });
    let rotation_runtime = Arc::new(
        chio_keyring::WitnessedRotationRuntime::new_enterprise(
            Arc::clone(&store),
            Arc::clone(&router),
            Arc::clone(&operator_backend),
            receipt_sink,
            Arc::new(migration_binding.clone()),
        )
        .map_err(|error| CliError::cli_other_error(error.to_string()))?,
    );
    let composition = KeyringRuntimeComposition {
        router,
        store,
        independent_services,
        rotation_runtime,
        startup_readiness,
        migration_binding,
        authority_backend,
        operator_backend,
        receipt_store,
        authority_rotation_lock: Arc::new(Mutex::new(())),
    };
    composition.ensure_bound_signing_topology()?;
    Ok(composition)
}

fn checkpoint_future_skew_millis(seconds: u64) -> Result<u64, CliError> {
    seconds.checked_mul(1_000).ok_or_else(|| {
        CliError::cli_other_error(
            "max_checkpoint_future_skew_seconds overflows milliseconds".to_string(),
        )
    })
}

fn parse_keyring_public_key(value: &str) -> Result<chio_core::PublicKey, CliError> {
    chio_core::PublicKey::from_hex(value)
        .map_err(|error| CliError::cli_other_error(error.to_string()))
}

fn parse_keyring_public_keys<I, F>(
    values: BTreeMap<String, String>,
    identifier: F,
) -> Result<BTreeMap<I, chio_core::PublicKey>, CliError>
where
    I: Ord,
    F: Fn(String) -> chio_keyring::Result<I>,
{
    values
        .into_iter()
        .map(|(name, key)| {
            Ok((
                identifier(name).map_err(|error| CliError::cli_other_error(error.to_string()))?,
                parse_keyring_public_key(&key)?,
            ))
        })
        .collect()
}

fn key_enterprise_receipt_to_chio_receipt(
    enterprise_receipt: &chio_keyring::SignedKeyEnterpriseReceipt,
    operator_backend: &dyn SigningBackend,
    configuration_binding: chio_core::Hash,
) -> Result<chio_core::receipt::body::ChioReceipt, CliError> {
    use chio_core::receipt::body::{ChioReceipt, ChioReceiptBody};
    use chio_core::receipt::decision::ToolCallAction;
    use chio_core::receipt::kinds::{
        BoundaryClass, ObservationOutcome, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel,
    };
    use chio_core::receipt::metadata::ActorRef;

    enterprise_receipt
        .verify_operator(&operator_backend.public_key())
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let canonical = enterprise_receipt
        .canonical_bytes()
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let action = ToolCallAction::from_parameters(serde_json::json!({
        "eventId": enterprise_receipt.body.event_id.as_str(),
        "eventSequence": enterprise_receipt.body.event_sequence,
        "receiptId": &enterprise_receipt.body.receipt_id,
        "stage": enterprise_receipt.body.stage,
    }))?;
    let body = ChioReceiptBody {
        id: enterprise_receipt.body.receipt_id.clone(),
        timestamp: enterprise_receipt.body.issued_at.div_ceil(1_000),
        capability_id: enterprise_receipt.body.transaction_id.clone(),
        tool_server: "chio.keyring".to_string(),
        tool_name: "authority_key_transition".to_string(),
        action,
        decision: None,
        receipt_kind: ReceiptKind::TraceObservation,
        boundary_class: BoundaryClass::DetectOnly,
        observation_outcome: Some(ObservationOutcome::Observed),
        tool_origin: ToolOrigin::ChioInternal,
        redaction_mode: RedactionMode::Redacted,
        actor_chain: vec![ActorRef {
            actor_id: enterprise_receipt.body.operator_key_id.to_string(),
            actor_kind: Some("key_log_operator".to_string()),
        }],
        content_hash: chio_core::crypto::sha256_hex(&canonical),
        policy_hash: configuration_binding.to_string(),
        evidence: Vec::new(),
        metadata: Some(serde_json::json!({
            "keyEnterpriseReceipt": enterprise_receipt,
        })),
        trust_level: TrustLevel::Verified,
        tenant_id: None,
        kernel_key: operator_backend.public_key(),
        bbs_projection_version: None,
    };
    ChioReceipt::sign_with_backend(body, operator_backend)
        .map_err(|error| CliError::cli_other_error(error.to_string()))
}

fn persist_key_enterprise_receipt(
    enterprise_receipt: &chio_keyring::SignedKeyEnterpriseReceipt,
    operator_backend: &dyn SigningBackend,
    configuration_binding: chio_core::Hash,
    receipt_store: &dyn chio_kernel::ReceiptStore,
    migration_binding: &KeyLogMigrationBinding,
) -> Result<bool, CliError> {
    migration_binding.require_enforced().map_err(|error| {
        CliError::cli_other_error(format!(
            "key-log verification migration denied enterprise receipt verification: {error}"
        ))
    })?;
    let receipt = key_enterprise_receipt_to_chio_receipt(
        enterprise_receipt,
        operator_backend,
        configuration_binding,
    )?;
    match receipt_store.load_chio_receipt(&receipt.id)? {
        Some(existing)
            if chio_core::canonical::canonical_json_bytes(&existing)?
                == chio_core::canonical::canonical_json_bytes(&receipt)? =>
        {
            Ok(false)
        }
        Some(_) => Err(CliError::cli_other_error(
            "normal receipt store contains conflicting key-enterprise evidence".to_string(),
        )),
        None => {
            migration_binding.require_enforced().map_err(|error| {
                CliError::cli_other_error(format!(
                    "key-log verification migration denied enterprise receipt persistence: {error}"
                ))
            })?;
            receipt_store.append_chio_receipt(&receipt)?;
            Ok(true)
        }
    }
}

fn load_existing_authority_keypair_with_identity(
    path: &Path,
) -> Result<(Keypair, PrivateFileIdentity), CliError> {
    let (bytes, identity) = read_private_file(path, 256)?;
    let seed_hex = std::str::from_utf8(&bytes)
        .map_err(|_| CliError::cli_other_error("authority seed is not valid UTF-8".to_string()))?;
    Keypair::from_seed_hex(seed_hex.trim())
        .map_err(CliError::from)
        .map(|keypair| (keypair, identity))
}

pub fn keyring_pending_authority_seed_path(active_seed_path: &Path) -> PathBuf {
    let mut value = active_seed_path.as_os_str().to_os_string();
    value.push(".chio-keyring-pending");
    PathBuf::from(value)
}

pub fn load_keyring_runtime_from_authority_seed(
    config_path: &Path,
    active_seed_path: &Path,
) -> Result<(Keypair, KeyringRuntimeComposition), CliError> {
    let (active, active_identity) =
        load_existing_authority_keypair_with_identity(active_seed_path)?;
    match load_keyring_runtime_composition(&active, config_path) {
        Ok(composition) => {
            cleanup_completed_authority_seed_handoff(active_seed_path, &active, &composition)?;
            Ok((active, composition))
        }
        Err(active_error) => {
            let pending_path = keyring_pending_authority_seed_path(active_seed_path);
            let (handoff, recovered, pending_identity) =
                match load_optional_authority_seed_handoff(&pending_path)? {
                    Some(value) => value,
                    None => return Err(active_error),
                };
            handoff.validate_keypair(&recovered)?;
            match load_keyring_runtime_composition(&recovered, config_path) {
                Ok(composition) => {
                    composition.require_key_log_verification()?;
                    let state = composition
                        .store
                        .load_state()
                        .map_err(|error| CliError::cli_other_error(error.to_string()))?
                        .ok_or_else(|| {
                            CliError::cli_other_error(
                                "keyring operator log is not initialized".to_string(),
                            )
                        })?;
                    if state.pending_event_id().is_some()
                        || state.signing_epoch() != handoff.target_epoch
                        || state
                            .active_signing_key()
                            .map_err(|error| CliError::cli_other_error(error.to_string()))?
                            .key_id
                            .to_string()
                            != handoff.key_id
                    {
                        return Err(active_error);
                    }
                    composition.require_key_log_verification()?;
                    write_authority_seed_file_bound(
                        active_seed_path,
                        &recovered,
                        Some(&active_identity),
                    )?;
                    composition.require_key_log_verification()?;
                    remove_authority_seed_handoff(&pending_path, &handoff, &pending_identity)?;
                    Ok((recovered, composition))
                }
                Err(_) => Err(active_error),
            }
        }
    }
}

const AUTHORITY_SEED_HANDOFF_SCHEMA: &str = "chio.authority-seed-handoff.v1";
static AUTHORITY_SEED_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Eq, PartialEq)]
struct PrivateFileIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    length: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct AuthoritySeedHandoff {
    schema: String,
    key_id: String,
    base_epoch: u64,
    target_epoch: u64,
    seed_hex: String,
}

impl AuthoritySeedHandoff {
    fn new(keypair: &Keypair, base_epoch: u64, target_epoch: u64) -> Result<Self, CliError> {
        if target_epoch
            != base_epoch.checked_add(1).ok_or_else(|| {
                CliError::cli_other_error("authority signing epoch overflow".to_string())
            })?
        {
            return Err(CliError::cli_other_error(
                "authority seed handoff target epoch is not contiguous".to_string(),
            ));
        }
        let public_key = keypair.public_key();
        let key_id = chio_keyring::derive_key_id(public_key.algorithm(), &public_key)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        Ok(Self {
            schema: AUTHORITY_SEED_HANDOFF_SCHEMA.to_string(),
            key_id: key_id.to_string(),
            base_epoch,
            target_epoch,
            seed_hex: keypair.seed_hex(),
        })
    }

    fn validate_keypair(&self, keypair: &Keypair) -> Result<(), CliError> {
        let expected_target = self.base_epoch.checked_add(1).ok_or_else(|| {
            CliError::cli_other_error("authority signing epoch overflow".to_string())
        })?;
        let public_key = keypair.public_key();
        let key_id = chio_keyring::derive_key_id(public_key.algorithm(), &public_key)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        if self.schema != AUTHORITY_SEED_HANDOFF_SCHEMA
            || self.target_epoch != expected_target
            || self.key_id != key_id.to_string()
            || self.seed_hex != keypair.seed_hex()
        {
            return Err(CliError::cli_other_error(
                "authority seed handoff identity or epoch binding is invalid".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QuiescentAuthoritySeedHandoff {
    Completed,
    Resumable { target_epoch: u64 },
}

fn classify_quiescent_authority_seed_handoff(
    handoff: &AuthoritySeedHandoff,
    active_epoch: u64,
    active_key_id: &str,
) -> Result<QuiescentAuthoritySeedHandoff, CliError> {
    if handoff.target_epoch == active_epoch && handoff.key_id == active_key_id {
        return Ok(QuiescentAuthoritySeedHandoff::Completed);
    }
    let target_epoch = active_epoch
        .checked_add(1)
        .ok_or_else(|| CliError::cli_other_error("authority signing epoch overflow".to_string()))?;
    if handoff.base_epoch == active_epoch && handoff.target_epoch == target_epoch {
        return Ok(QuiescentAuthoritySeedHandoff::Resumable { target_epoch });
    }
    Err(CliError::cli_other_error(
        "stale pending authority seed is not bound to the active epoch".to_string(),
    ))
}

fn persist_authority_seed_handoff(
    path: &Path,
    handoff: &AuthoritySeedHandoff,
) -> Result<PrivateFileIdentity, CliError> {
    let bytes = chio_core::canonical::canonical_json_bytes(handoff)?;
    atomic_write_private_file(path, &bytes, None).map_err(CliError::Io)
}

fn load_authority_seed_handoff(
    path: &Path,
) -> Result<(AuthoritySeedHandoff, Keypair, PrivateFileIdentity), CliError> {
    let (bytes, identity) = read_private_file(path, 1_024)?;
    let handoff: AuthoritySeedHandoff = serde_json::from_slice(&bytes)?;
    let keypair = Keypair::from_seed_hex(&handoff.seed_hex)?;
    handoff.validate_keypair(&keypair)?;
    Ok((handoff, keypair, identity))
}

fn load_optional_authority_seed_handoff(
    path: &Path,
) -> Result<Option<(AuthoritySeedHandoff, Keypair, PrivateFileIdentity)>, CliError> {
    match load_authority_seed_handoff(path) {
        Ok(value) => Ok(Some(value)),
        Err(CliError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn cleanup_completed_authority_seed_handoff(
    active_seed_path: &Path,
    active_keypair: &Keypair,
    composition: &KeyringRuntimeComposition,
) -> Result<(), CliError> {
    composition.require_key_log_verification()?;
    let pending_path = keyring_pending_authority_seed_path(active_seed_path);
    let Some((handoff, pending_keypair, identity)) =
        load_optional_authority_seed_handoff(&pending_path)?
    else {
        return Ok(());
    };
    let state = composition
        .store
        .load_state()
        .map_err(|error| CliError::cli_other_error(error.to_string()))?
        .ok_or_else(|| {
            CliError::cli_other_error("keyring operator log is not initialized".to_string())
        })?;
    if state.pending_event_id().is_some() {
        let pending = state.pending_rotation_key().ok_or_else(|| {
            CliError::cli_other_error("pending rotation is missing its key".to_string())
        })?;
        if handoff.base_epoch != state.signing_epoch()
            || handoff.target_epoch
                != state.signing_epoch().checked_add(1).ok_or_else(|| {
                    CliError::cli_other_error("authority signing epoch overflow".to_string())
                })?
            || handoff.key_id != pending.key_id.to_string()
        {
            return Err(CliError::cli_other_error(
                "pending authority seed does not match the durable rotation".to_string(),
            ));
        }
        return Ok(());
    }
    let active_public_key = active_keypair.public_key();
    let active_key_id =
        chio_keyring::derive_key_id(active_public_key.algorithm(), &active_public_key)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    match classify_quiescent_authority_seed_handoff(
        &handoff,
        state.signing_epoch(),
        &active_key_id.to_string(),
    )? {
        QuiescentAuthoritySeedHandoff::Completed => {
            if pending_keypair.public_key() != active_public_key {
                return Err(CliError::cli_other_error(
                    "completed authority seed handoff does not match the active key".to_string(),
                ));
            }
            composition.require_key_log_verification()?;
            remove_authority_seed_handoff(&pending_path, &handoff, &identity)
        }
        QuiescentAuthoritySeedHandoff::Resumable { .. } => Ok(()),
    }
}

fn remove_authority_seed_handoff(
    path: &Path,
    expected: &AuthoritySeedHandoff,
    expected_identity: &PrivateFileIdentity,
) -> Result<(), CliError> {
    let (current, _, identity) = load_authority_seed_handoff(path)?;
    if &current != expected || &identity != expected_identity {
        return Err(CliError::cli_other_error(
            "pending authority seed changed before cleanup".to_string(),
        ));
    }
    fs::remove_file(path)?;
    sync_parent_directory(path)?;
    Ok(())
}

fn write_authority_seed_file_bound(
    path: &Path,
    keypair: &Keypair,
    expected_identity: Option<&PrivateFileIdentity>,
) -> Result<PrivateFileIdentity, CliError> {
    atomic_write_private_file(
        path,
        format!("{}\n", keypair.seed_hex()).as_bytes(),
        expected_identity,
    )
    .map_err(CliError::Io)
}

fn read_private_file(
    path: &Path,
    maximum_bytes: usize,
) -> Result<(Vec<u8>, PrivateFileIdentity), std::io::Error> {
    let path_metadata = fs::symlink_metadata(path)?;
    validate_private_file_metadata(&path_metadata)?;
    #[cfg(unix)]
    let mut file = {
        use rustix::fs::{open, Mode, OFlags};

        let descriptor = open(
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|error| std::io::Error::from_raw_os_error(error.raw_os_error()))?;
        File::from(descriptor)
    };
    #[cfg(not(unix))]
    let mut file = OpenOptions::new().read(true).open(path)?;
    let opened_metadata = file.metadata()?;
    validate_private_file_metadata(&opened_metadata)?;
    let expected_identity = identity_from_metadata(&path_metadata);
    if identity_from_metadata(&opened_metadata) != expected_identity {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "private file changed while it was opened",
        ));
    }
    let limit = u64::try_from(maximum_bytes)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "file limit"))?
        .checked_add(1)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "file limit"))?;
    let mut bytes = Vec::with_capacity(maximum_bytes);
    Read::by_ref(&mut file)
        .take(limit)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "private file exceeds its byte limit",
        ));
    }
    let final_path_metadata = fs::symlink_metadata(path)?;
    validate_private_file_metadata(&final_path_metadata)?;
    if identity_from_metadata(&final_path_metadata) != expected_identity
        || identity_from_metadata(&file.metadata()?) != expected_identity
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "private file identity changed while it was read",
        ));
    }
    Ok((bytes, expected_identity))
}

fn load_private_seed_backend(path: &Path) -> Result<chio_core::crypto::Ed25519Backend, CliError> {
    let (mut bytes, _) = read_private_file(path, 32)?;
    if bytes.len() != 32 {
        bytes.fill(0);
        return Err(CliError::cli_other_error(
            "signing seed must contain exactly 32 bytes".to_string(),
        ));
    }
    let mut seed = [0_u8; 32];
    seed.copy_from_slice(&bytes);
    bytes.fill(0);
    let keypair = Keypair::from_seed(&seed);
    seed.fill(0);
    Ok(chio_core::crypto::Ed25519Backend::new(keypair))
}

fn private_file_identity(path: &Path) -> Result<PrivateFileIdentity, std::io::Error> {
    let metadata = fs::symlink_metadata(path)?;
    validate_private_file_metadata(&metadata)?;
    Ok(identity_from_metadata(&metadata))
}

fn validate_private_file_metadata(metadata: &fs::Metadata) -> Result<(), std::io::Error> {
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "private key material must be a regular file",
        ));
    }
    #[cfg(unix)]
    if metadata.nlink() != 1 || metadata.mode() & 0o177 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "private key material must be singly linked with mode 0600 or stricter",
        ));
    }
    Ok(())
}

fn identity_from_metadata(metadata: &fs::Metadata) -> PrivateFileIdentity {
    PrivateFileIdentity {
        #[cfg(unix)]
        device: metadata.dev(),
        #[cfg(unix)]
        inode: metadata.ino(),
        length: metadata.len(),
    }
}

fn atomic_write_private_file(
    path: &Path,
    bytes: &[u8],
    expected_identity: Option<&PrivateFileIdentity>,
) -> Result<PrivateFileIdentity, std::io::Error> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let parent_metadata = fs::symlink_metadata(parent)?;
    if !parent_metadata.file_type().is_dir() || parent_metadata.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "private key parent must be a regular directory",
        ));
    }
    validate_destination_identity(path, expected_identity)?;
    let mut temp_path = None;
    let mut temp_file = None;
    for _ in 0..128 {
        let counter = AUTHORITY_SEED_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut name = path.file_name().unwrap_or_default().to_os_string();
        name.push(format!(".{}.{}.tmp", std::process::id(), counter));
        let candidate = parent.join(name);
        #[cfg(unix)]
        let opened = {
            use rustix::fs::{open, Mode, OFlags};

            open(
                &candidate,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::RUSR | Mode::WUSR,
            )
            .map(File::from)
            .map_err(|error| std::io::Error::from_raw_os_error(error.raw_os_error()))
        };
        #[cfg(not(unix))]
        let opened = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate);
        match opened {
            Ok(file) => {
                temp_path = Some(candidate);
                temp_file = Some(file);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    let temp_path = temp_path.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "unable to allocate a unique private-key temp file",
        )
    })?;
    let result = (|| {
        let mut file =
            temp_file.ok_or_else(|| std::io::Error::other("private temp file missing"))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        validate_private_file_metadata(&file.metadata()?)?;
        validate_destination_identity(path, expected_identity)?;
        fs::rename(&temp_path, path)?;
        sync_parent_directory(path)?;
        private_file_identity(path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

fn validate_destination_identity(
    path: &Path,
    expected_identity: Option<&PrivateFileIdentity>,
) -> Result<(), std::io::Error> {
    match (private_file_identity(path), expected_identity) {
        (Ok(actual), Some(expected)) if &actual == expected => Ok(()),
        (Ok(_), Some(_)) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "private key destination identity changed",
        )),
        (Err(error), None) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        (Ok(_), None) => Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "private key destination already exists",
        )),
        (Err(error), _) => Err(error),
    }
}

fn sync_parent_directory(path: &Path) -> Result<(), std::io::Error> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    File::open(parent)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_test_support::prelude::*;

    #[test]
    fn keyring_runtime_config_requires_complete_migration_and_service_topology() {
        let deployment_id = "deployment.keyring.config.test";
        let transition_signer = Keypair::from_seed(&[0x33; 32]).public_key();
        let bootstrap = Keypair::from_seed(&[0x34; 32]).public_key();
        let operator = Keypair::from_seed(&[0x35; 32]).public_key();
        let artifact_time = Keypair::from_seed(&[0x36; 32]).public_key();
        let witness_a = Keypair::from_seed(&[0x37; 32]).public_key();
        let witness_b = Keypair::from_seed(&[0x38; 32]).public_key();
        let witness_c = Keypair::from_seed(&[0x39; 32]).public_key();
        let audit_a = Keypair::from_seed(&[0x3a; 32]).public_key();
        let audit_b = Keypair::from_seed(&[0x3b; 32]).public_key();
        let value = serde_json::json!({
            "schema": "chio.keyring.runtime-config.v1",
            "database_path": "/var/lib/chio/key-log.sqlite3",
            "enterprise_migration": {
                "state_database_path": "/var/lib/chio/key-log-migration.sqlite3",
                "deployment_id": deployment_id,
                "stage": "enforced",
                "trusted_transition_signers": [transition_signer.to_hex()],
                "minimum_heads": [{
                    "key": {
                        "deployment_id": deployment_id,
                        "scope_kind": "deployment",
                        "scope_id": deployment_id,
                        "control": "key_log_verification"
                    },
                    "minimum_generation": 2,
                    "transition_digest": vec![1_u8; 32]
                }]
            },
            "log_id": "production.authority.log",
            "authority_id": "production.authority",
            "bootstrap_public_key": bootstrap.to_hex(),
            "operator_public_key": operator.to_hex(),
            "operator_seed_file_path": "/run/chio/operator.seed",
            "witness_roster_id": "production.witnesses.v1",
            "witness_public_keys": {
                "witness.a": witness_a.to_hex(),
                "witness.b": witness_b.to_hex(),
                "witness.c": witness_c.to_hex()
            },
            "witness_service_endpoints": {
                "witness.a": "/run/chio/witness-a.sock",
                "witness.b": "/run/chio/witness-b.sock",
                "witness.c": "/run/chio/witness-c.sock"
            },
            "audit_service_endpoints": {
                "audit.a": "/run/chio/audit-a.sock",
                "audit.b": "/run/chio/audit-b.sock"
            },
            "audit_public_keys": {
                "audit.a": audit_a.to_hex(),
                "audit.b": audit_b.to_hex()
            },
            "recovery_policy_id": "production.recovery.v1",
            "recovery_public_keys": {},
            "recovery_threshold": 0,
            "artifact_time_public_keys": {
                "timestamp.primary": artifact_time.to_hex()
            },
            "artifact_time_seed_file_path": "/run/chio/artifact-time.seed",
            "max_checkpoint_future_skew_seconds": 30
        });

        let config: KeyringRuntimeConfig = serde_json::from_value(value).test_unwrap();
        let key = config.enterprise_migration.validated_key().test_unwrap();
        assert_eq!(key.deployment_id.as_str(), deployment_id);
        assert_eq!(key.scope_id.as_str(), deployment_id);
        assert_eq!(config.witness_public_keys.len(), 3);
        assert_eq!(config.audit_public_keys.len(), 2);
    }
}
