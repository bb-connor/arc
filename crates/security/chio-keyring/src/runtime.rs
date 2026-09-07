use std::collections::BTreeSet;
use std::sync::Arc;

use chio_core_types::{Hash, SigningBackend};

use crate::{
    CheckpointStage, EventId, IndependentKeyLogServices, KeyEnterpriseReceiptStage, KeyLogPin,
    KeyLogSyncResponse, KeyringError, KeyringSigningRouter, Result, SignedKeyEnterpriseReceipt,
    SignedKeyLogCheckpoint, SignedKeyLogEvent, SqliteKeyLogStore, StagedPendingBackend, WitnessId,
    WitnessSignature,
};

const MAX_RUNTIME_SYNC_PAGES: usize = 4_096;

pub trait KeyLogWitnessClient: Send + Sync {
    fn witness_id(&self) -> &WitnessId;
    fn pin(&self) -> Result<Option<KeyLogPin>>;
    fn sign_candidate(
        &self,
        candidate: &SignedKeyLogCheckpoint,
        synchronization: &KeyLogSyncResponse,
    ) -> Result<WitnessSignature>;
}

pub trait KeyEnterpriseReceiptSink: Send + Sync {
    fn persist(&self, receipt: &SignedKeyEnterpriseReceipt) -> Result<()>;
}

/// Final admission check run after witness and auditor synchronization and
/// immediately before the selector activation transaction.
pub trait KeyLogActivationGuard: Send + Sync {
    fn require_activation(&self) -> Result<()>;
}

pub struct PendingWitnessedRotation {
    pub event_id: EventId,
    pub checkpoint: SignedKeyLogCheckpoint,
    pub checkpoint_hash: Hash,
    staged_backend: StagedPendingBackend,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessedRotationOutcome {
    pub checkpoint_hash: Hash,
    pub signing_epoch: u64,
    pub audit_pin: KeyLogPin,
}

pub struct WitnessedRotationRuntime {
    store: Arc<SqliteKeyLogStore>,
    router: Arc<KeyringSigningRouter>,
    operator: Arc<dyn SigningBackend>,
    mode: WitnessedRotationMode,
}

enum WitnessedRotationMode {
    Standard,
    Enterprise {
        receipt_sink: Arc<dyn KeyEnterpriseReceiptSink>,
        activation_guard: Arc<dyn KeyLogActivationGuard>,
    },
}

impl WitnessedRotationRuntime {
    pub fn new(
        store: Arc<SqliteKeyLogStore>,
        router: Arc<KeyringSigningRouter>,
        operator: Arc<dyn SigningBackend>,
    ) -> Result<Self> {
        Self::new_inner(store, router, operator, WitnessedRotationMode::Standard)
    }

    pub fn new_enterprise(
        store: Arc<SqliteKeyLogStore>,
        router: Arc<KeyringSigningRouter>,
        operator: Arc<dyn SigningBackend>,
        enterprise_receipt_sink: Arc<dyn KeyEnterpriseReceiptSink>,
        activation_guard: Arc<dyn KeyLogActivationGuard>,
    ) -> Result<Self> {
        Self::new_inner(
            store,
            router,
            operator,
            WitnessedRotationMode::Enterprise {
                receipt_sink: enterprise_receipt_sink,
                activation_guard,
            },
        )
    }

    fn new_inner(
        store: Arc<SqliteKeyLogStore>,
        router: Arc<KeyringSigningRouter>,
        operator: Arc<dyn SigningBackend>,
        mode: WitnessedRotationMode,
    ) -> Result<Self> {
        match (&mode, router.requires_enterprise_activation_guard()) {
            (WitnessedRotationMode::Standard, true) => {
                return Err(KeyringError::StateInvariant(
                    "enterprise router requires the guarded enterprise rotation runtime",
                ));
            }
            (WitnessedRotationMode::Enterprise { .. }, false) => {
                return Err(KeyringError::StateInvariant(
                    "enterprise rotation runtime requires an enterprise router",
                ));
            }
            _ => {}
        }
        if !router.uses_store(&store) {
            return Err(KeyringError::StateInvariant(
                "rotation runtime router and operator log use different stores",
            ));
        }
        let policy = store.policy_clone();
        if operator.public_key() != *policy.operator_public_key()
            || operator.algorithm() != policy.operator_public_key().algorithm()
        {
            return Err(KeyringError::StateInvariant(
                "rotation runtime operator backend does not match the durable policy",
            ));
        }
        Ok(Self {
            store,
            router,
            operator,
            mode,
        })
    }

    pub fn begin_rotation(
        &self,
        event: &SignedKeyLogEvent,
        pending_backend: Box<dyn SigningBackend>,
    ) -> Result<PendingWitnessedRotation> {
        let checkpoint = self.store.append_event(event, self.operator.as_ref())?;
        self.persist_enterprise_receipt(&event.body.event_id, KeyEnterpriseReceiptStage::Pending)?;
        let checkpoint_hash = checkpoint.checkpoint_hash()?;
        let staged_backend = self
            .router
            .stage_pending(event.body.event_id.clone(), pending_backend)?;
        Ok(PendingWitnessedRotation {
            event_id: event.body.event_id.clone(),
            checkpoint,
            checkpoint_hash,
            staged_backend,
        })
    }

    /// Reconstructs the volatile pending-key lease from a validated durable
    /// pending tail after a clean or crashed runtime restart.
    pub fn resume_pending_rotation(
        &self,
        pending_backend: Box<dyn SigningBackend>,
    ) -> Result<PendingWitnessedRotation> {
        if !matches!(
            self.store.head_stage()?,
            Some(CheckpointStage::Pending | CheckpointStage::Witnessed)
        ) {
            return Err(KeyringError::StateInvariant(
                "key log does not have a pending rotation to resume",
            ));
        }
        let state = self
            .store
            .load_state()?
            .ok_or(KeyringError::StateInvariant("key log is not initialized"))?;
        let event_id = state
            .pending_event_id()
            .cloned()
            .ok_or(KeyringError::StateInvariant(
                "pending checkpoint is missing a pending selector event",
            ))?;
        let event =
            self.store
                .load_events()?
                .into_iter()
                .last()
                .ok_or(KeyringError::StateInvariant(
                    "pending selector event is absent from the durable log",
                ))?;
        if event.body.event_id != event_id {
            return Err(KeyringError::StateInvariant(
                "pending selector event does not match the durable log tail",
            ));
        }
        let stored = self.store.load_checkpoints()?.into_iter().last().ok_or(
            KeyringError::StateInvariant("pending checkpoint is absent from the durable log"),
        )?;
        if !matches!(
            stored.stage,
            CheckpointStage::Pending | CheckpointStage::Witnessed
        ) || stored.checkpoint.body.checkpoint_sequence != event.body.sequence
        {
            return Err(KeyringError::StateInvariant(
                "pending checkpoint does not match the durable event tail",
            ));
        }
        let checkpoint = stored.checkpoint;
        let checkpoint_hash = checkpoint.checkpoint_hash()?;
        let staged_backend = self
            .router
            .stage_pending(event_id.clone(), pending_backend)?;
        Ok(PendingWitnessedRotation {
            event_id,
            checkpoint,
            checkpoint_hash,
            staged_backend,
        })
    }

    pub fn collect_witnesses_and_activate(
        &self,
        pending: &mut PendingWitnessedRotation,
        services: &IndependentKeyLogServices,
    ) -> Result<WitnessedRotationOutcome> {
        self.collect_witnesses_and_wait_for_auditors(pending, services)?;
        self.activate_and_confirm(pending, services)
    }

    fn collect_witnesses_and_wait_for_auditors(
        &self,
        pending: &mut PendingWitnessedRotation,
        services: &IndependentKeyLogServices,
    ) -> Result<()> {
        if services.configuration_binding() != self.store.configuration_binding()? {
            return Err(KeyringError::StateInvariant(
                "rotation runtime and external services use different policy bindings",
            ));
        }
        let mut witness_ids = BTreeSet::new();
        self.store
            .verified_checkpoint_stage(&pending.checkpoint_hash)?;
        for witness in services.witnesses() {
            if !witness_ids.insert(witness.witness_id().clone()) {
                return Err(KeyringError::DuplicateIdentifier);
            }
            match self.synchronize_witness_to_candidate(witness, &pending.checkpoint) {
                Ok(signature) => {
                    if &signature.witness_id != witness.witness_id() {
                        return Err(KeyringError::InvalidSignature);
                    }
                    self.store
                        .store_witness_signature(&pending.checkpoint_hash, &signature)?;
                }
                Err(KeyringError::Io(_)) => {}
                Err(error) => return Err(error),
            }
        }
        let target_stage = self
            .store
            .verified_checkpoint_stage(&pending.checkpoint_hash)?;
        if target_stage != CheckpointStage::Witnessed && target_stage != CheckpointStage::Activated
        {
            return Err(KeyringError::InvalidWitnessActivation);
        }

        let witnessed_pin = self
            .store
            .head_pin()?
            .ok_or(KeyringError::StateInvariant("operator key log has no head"))?;
        self.wait_for_independent_auditors(services, &witnessed_pin)?;
        Ok(())
    }

    fn activate_and_confirm(
        &self,
        pending: &mut PendingWitnessedRotation,
        services: &IndependentKeyLogServices,
    ) -> Result<WitnessedRotationOutcome> {
        match &self.mode {
            WitnessedRotationMode::Standard => self.router.activate_rotation(
                &mut pending.staged_backend,
                &pending.checkpoint_hash,
                self.operator.as_ref(),
            )?,
            WitnessedRotationMode::Enterprise {
                activation_guard, ..
            } => {
                self.router.activate_rotation_guarded(
                    &mut pending.staged_backend,
                    &pending.checkpoint_hash,
                    self.operator.as_ref(),
                    activation_guard.as_ref(),
                )?;
                activation_guard.require_activation()?;
            }
        }
        for witness in services.witnesses() {
            match self.synchronize_witness_to_candidate(witness, &pending.checkpoint) {
                Ok(signature) => {
                    self.store
                        .store_witness_signature(&pending.checkpoint_hash, &signature)?;
                }
                Err(KeyringError::Io(_)) => {}
                Err(error) => return Err(error),
            }
        }
        let activated_pin = self
            .store
            .head_pin()?
            .ok_or(KeyringError::StateInvariant("operator key log has no head"))?;
        self.wait_for_independent_auditors(services, &activated_pin)?;
        let signing_epoch = self.router.signing_epoch()?;
        if activated_pin.signing_epoch != signing_epoch {
            return Err(KeyringError::StateInvariant(
                "independent auditors did not observe the activated signing epoch",
            ));
        }
        self.persist_enterprise_receipt(&pending.event_id, KeyEnterpriseReceiptStage::Active)?;
        Ok(WitnessedRotationOutcome {
            checkpoint_hash: pending.checkpoint_hash,
            signing_epoch,
            audit_pin: activated_pin,
        })
    }

    fn wait_for_independent_auditors(
        &self,
        services: &IndependentKeyLogServices,
        expected_pin: &KeyLogPin,
    ) -> Result<()> {
        services.request_audit_poll()?;
        for _ in 0..250 {
            match services.audit_quorum_at_pin(&self.store.policy_clone(), expected_pin) {
                Ok(()) => return Ok(()),
                Err(KeyringError::Io(_))
                | Err(KeyringError::StateInvariant(_))
                | Err(KeyringError::InvalidWitnessActivation) => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(error) => return Err(error),
            }
        }
        Err(KeyringError::StateInvariant(
            "independent audit monitors did not reach the operator head",
        ))
    }

    fn synchronize_witness_to_candidate(
        &self,
        witness: &dyn KeyLogWitnessClient,
        target: &SignedKeyLogCheckpoint,
    ) -> Result<WitnessSignature> {
        let target_hash = target.checkpoint_hash()?;
        for _ in 0..MAX_RUNTIME_SYNC_PAGES {
            let pin = witness.pin()?;
            let response = self.store.synchronization_response(pin.as_ref())?;
            let candidate = match response.checkpoints.last() {
                Some(checkpoint) => checkpoint,
                None if pin
                    .as_ref()
                    .is_some_and(|pin| pin.checkpoint_hash == target_hash) =>
                {
                    target
                }
                None => {
                    return Err(KeyringError::InvalidCheckpoint(
                        "witness synchronization did not reach the pending checkpoint",
                    ));
                }
            };
            let signature = witness.sign_candidate(candidate, &response)?;
            let candidate_hash = candidate.checkpoint_hash()?;
            self.store
                .store_witness_signature(&candidate_hash, &signature)?;
            if candidate_hash == target_hash {
                return Ok(signature);
            }
        }
        Err(KeyringError::InvalidCheckpoint(
            "witness synchronization exceeded its page limit",
        ))
    }

    fn persist_enterprise_receipt(
        &self,
        event_id: &EventId,
        stage: KeyEnterpriseReceiptStage,
    ) -> Result<()> {
        let sink = match &self.mode {
            WitnessedRotationMode::Standard => return Ok(()),
            WitnessedRotationMode::Enterprise { receipt_sink, .. } => receipt_sink,
        };
        let receipt = self
            .store
            .load_enterprise_receipts()?
            .into_iter()
            .find(|receipt| &receipt.body.event_id == event_id && receipt.body.stage == stage)
            .ok_or(KeyringError::StateInvariant(
                "key rotation is missing its enterprise receipt",
            ))?;
        sink.persist(&receipt)
    }
}
