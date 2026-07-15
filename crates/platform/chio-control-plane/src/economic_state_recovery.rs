use std::sync::Arc;
use std::time::Duration;

use chio_core::economic_continuity::{
    verify_economic_idempotent_recovery, verify_economic_state_batch_advance,
    verify_economic_state_batch_commit, verify_economic_state_view, verify_economic_target_status,
    EconomicAdmissionHandoffStateV1, EconomicAdmissionHandoffV1, EconomicAdmissionHandoffVerifier,
    EconomicCheckpointReadQuery, EconomicEffectSlotV1, EconomicEffectStateV1,
    EconomicIdempotentTargetVerifier, EconomicRequestKeyV1, EconomicStateAnchor,
    EconomicStateAnchorError, EconomicStateAnchorPins, EconomicStateReadQuery,
    EconomicTargetStatusVerifier, EconomicTransitionProofVerifier,
    VerifiedEconomicIdempotentRecovery, VerifiedEconomicStateBatchAdvance,
    VerifiedEconomicTargetStatus,
};
use chio_kernel::admission_operation::{
    AdmissionIdentifier, AdmissionOperationId, AdmissionOperationKind, AdmissionOperationState,
    AdmissionOperationStoreError, QualifiedAdmissionOperationStore,
    QualifiedAdmissionOperationStoreExt, StoreMutationFence,
};
use chio_store_sqlite::{
    EconomicOperationStageBinding, EconomicStateCacheError, EconomicStateStageRecord,
    EconomicStateStageStatus, SqliteEconomicStateCache,
};

const MAX_RECOVERY_LEASE_DURATION: Duration = Duration::from_secs(5 * 60);
const I_JSON_MAX_SAFE_INTEGER: u64 = (1_u64 << 53) - 1;

#[derive(Debug, thiserror::Error)]
pub enum EconomicStateRecoveryError {
    #[error(transparent)]
    Cache(#[from] EconomicStateCacheError),
    #[error(transparent)]
    Anchor(#[from] EconomicStateAnchorError),
    #[error(transparent)]
    Admission(#[from] AdmissionOperationStoreError),
    #[error("economic recovery configuration is invalid: {0}")]
    InvalidConfiguration(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EconomicRecoveryOutcome {
    Finalized(EconomicStateStageRecord),
    Discarded(EconomicStateStageRecord),
    Quarantined(EconomicStateStageRecord),
    Pending(EconomicStateStageRecord),
}

#[derive(Debug)]
pub enum EconomicEffectRecoveryDecision {
    TargetStatus(VerifiedEconomicTargetStatus),
    IdempotentRetry(VerifiedEconomicIdempotentRecovery),
    LockedUnknown(EconomicEffectRecoveryLock),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EconomicEffectRecoveryLock {
    next_slot: EconomicEffectSlotV1,
}

impl EconomicEffectRecoveryLock {
    #[must_use]
    pub fn next_slot(&self) -> &EconomicEffectSlotV1 {
        &self.next_slot
    }
}

pub fn qualify_committed_effect_recovery(
    slot: &EconomicEffectSlotV1,
    target_status: Option<(&str, &dyn EconomicTargetStatusVerifier)>,
    idempotent_target: Option<&dyn EconomicIdempotentTargetVerifier>,
) -> Result<EconomicEffectRecoveryDecision, EconomicStateAnchorError> {
    slot.validate()?;
    if !matches!(
        slot.state,
        EconomicEffectStateV1::DispatchCommitted | EconomicEffectStateV1::Unknown
    ) || target_status.is_some() && idempotent_target.is_some()
    {
        return Err(EconomicStateAnchorError::IdempotentRecoveryRejected);
    }
    if let Some((evidence_digest, verifier)) = target_status {
        return Ok(
            match verify_economic_target_status(slot, evidence_digest, verifier) {
                Ok(status) => EconomicEffectRecoveryDecision::TargetStatus(status),
                Err(_) => EconomicEffectRecoveryDecision::LockedUnknown(unknown_lock(slot)?),
            },
        );
    }
    if let Some(verifier) = idempotent_target {
        return Ok(match verify_economic_idempotent_recovery(slot, verifier) {
            Ok(retry) => EconomicEffectRecoveryDecision::IdempotentRetry(retry),
            Err(_) => EconomicEffectRecoveryDecision::LockedUnknown(unknown_lock(slot)?),
        });
    }
    Ok(EconomicEffectRecoveryDecision::LockedUnknown(unknown_lock(
        slot,
    )?))
}

fn unknown_lock(
    slot: &EconomicEffectSlotV1,
) -> Result<EconomicEffectRecoveryLock, EconomicStateAnchorError> {
    let mut next_slot = slot.clone();
    if slot.state == EconomicEffectStateV1::DispatchCommitted {
        next_slot.state = EconomicEffectStateV1::Unknown;
        slot.validate_successor(&next_slot)?;
    }
    Ok(EconomicEffectRecoveryLock { next_slot })
}

pub struct EconomicStateRecovery {
    cache: SqliteEconomicStateCache,
    anchor: Arc<dyn EconomicStateAnchor>,
    operations: Arc<dyn QualifiedAdmissionOperationStore>,
    transition_verifier: Arc<dyn EconomicTransitionProofVerifier>,
    pins: EconomicStateAnchorPins,
    active_fence: StoreMutationFence,
    claimant_id: AdmissionIdentifier,
    recovery_lease_duration: Duration,
}

impl EconomicStateRecovery {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cache: SqliteEconomicStateCache,
        anchor: Arc<dyn EconomicStateAnchor>,
        operations: Arc<dyn QualifiedAdmissionOperationStore>,
        transition_verifier: Arc<dyn EconomicTransitionProofVerifier>,
        pins: EconomicStateAnchorPins,
        active_fence: StoreMutationFence,
        claimant_id: AdmissionIdentifier,
        recovery_lease_duration: Duration,
    ) -> Result<Self, EconomicStateRecoveryError> {
        pins.validate()?;
        if recovery_lease_duration.is_zero()
            || recovery_lease_duration > MAX_RECOVERY_LEASE_DURATION
            || active_fence.store_uuid.is_empty()
            || active_fence.lease_id.is_empty()
            || active_fence.owner_epoch == 0
        {
            return Err(EconomicStateRecoveryError::InvalidConfiguration(
                "pins, serving fence, and lease duration must be bounded and nonzero".to_owned(),
            ));
        }
        Ok(Self {
            cache,
            anchor,
            operations,
            transition_verifier,
            pins,
            active_fence,
            claimant_id,
            recovery_lease_duration,
        })
    }

    pub fn recover_stage(
        &self,
        batch_id: &str,
        trusted_now_unix_ms: u64,
    ) -> Result<EconomicRecoveryOutcome, EconomicStateRecoveryError> {
        validate_trusted_time(trusted_now_unix_ms)?;
        let stage = self
            .cache
            .load_stage(batch_id)?
            .ok_or(EconomicStateCacheError::NotFound)?;
        match stage.status() {
            EconomicStateStageStatus::DbFinalized => {
                return Ok(EconomicRecoveryOutcome::Finalized(stage))
            }
            EconomicStateStageStatus::Discarded => {
                return Ok(EconomicRecoveryOutcome::Discarded(stage))
            }
            EconomicStateStageStatus::Quarantined => {
                return Ok(EconomicRecoveryOutcome::Quarantined(stage))
            }
            EconomicStateStageStatus::EconomicAnchorAdvanced => {
                return self.finalize(stage, trusted_now_unix_ms)
            }
            EconomicStateStageStatus::DbStaged => {}
        }

        let current = verify_economic_state_view(stage.base_view().clone(), &self.pins)?;
        let advance = verify_economic_state_batch_advance(
            &current,
            stage.batch().clone(),
            &self.pins,
            self.transition_verifier.as_ref(),
        )?;
        let query = state_query(advance.batch());
        let observed = match self.anchor.read_state(&query) {
            Ok(observed) => observed,
            Err(_) => return Ok(EconomicRecoveryOutcome::Pending(stage)),
        };
        let base = advance.current().view();
        let batch = advance.batch();

        if observed.view().checkpoint_sequence == batch.checkpoint_sequence {
            if observed.view().checkpoint_digest != batch.checkpoint_digest {
                return self.quarantine(
                    stage,
                    "external anchor checkpoint conflicts with the staged batch",
                    trusted_now_unix_ms,
                );
            }
            return self.record_and_finalize(&advance, &observed, trusted_now_unix_ms);
        }

        if observed.view().checkpoint_sequence > batch.checkpoint_sequence {
            let retained_query = EconomicCheckpointReadQuery {
                checkpoint_sequence: batch.checkpoint_sequence,
                checkpoint_digest: batch.checkpoint_digest.clone(),
                query,
            };
            let retained = match self.anchor.read_checkpoint_state(&retained_query) {
                Ok(retained) => retained,
                Err(_) => return Ok(EconomicRecoveryOutcome::Pending(stage)),
            };
            return self.record_and_finalize(&advance, &retained, trusted_now_unix_ms);
        }

        if observed.view().checkpoint_sequence < base.checkpoint_sequence {
            return Ok(EconomicRecoveryOutcome::Pending(stage));
        }
        if observed.view().checkpoint_sequence != base.checkpoint_sequence
            || observed.view().checkpoint_digest != base.checkpoint_digest
        {
            return self.quarantine(
                stage,
                "external anchor predecessor diverges from the staged batch",
                trusted_now_unix_ms,
            );
        }

        if let Some(binding) = stage.operation_binding() {
            if !self.operation_authorizes_retry(binding, trusted_now_unix_ms)? {
                let discarded = self.cache.discard_unanchored_stage(
                    batch_id,
                    "admission operation no longer authorizes the unanchored batch",
                    &self.active_fence,
                    trusted_now_unix_ms,
                )?;
                return Ok(EconomicRecoveryOutcome::Discarded(discarded));
            }
        }

        match self.anchor.compare_and_swap_batch(&advance) {
            Ok(committed) => self.record_and_finalize(&advance, &committed, trusted_now_unix_ms),
            Err(_) => self.resolve_uncertain_cas(stage, &advance, trusted_now_unix_ms),
        }
    }

    pub fn recover_pending(
        &self,
        limit: usize,
        trusted_now_unix_ms: u64,
    ) -> Result<Vec<EconomicRecoveryOutcome>, EconomicStateRecoveryError> {
        let stages = self.cache.list_pending(limit)?;
        stages
            .iter()
            .map(|stage| self.recover_stage(&stage.batch().batch_id, trusted_now_unix_ms))
            .collect()
    }

    fn operation_authorizes_retry(
        &self,
        binding: &EconomicOperationStageBinding,
        trusted_now_unix_ms: u64,
    ) -> Result<bool, EconomicStateRecoveryError> {
        let operation_id = AdmissionOperationId::from_persisted(binding.operation_id().to_owned())
            .map_err(|error| EconomicStateRecoveryError::InvalidConfiguration(error.to_string()))?;
        let Some(operation) = self.operations.load_by_operation_id(&operation_id)? else {
            return Ok(false);
        };
        if operation.state().is_terminal()
            || operation.state() != binding.operation_state()
            || operation.version() != binding.operation_version()
            || operation.coordinator_lease_epoch() != binding.coordinator_lease_epoch()
        {
            return Ok(false);
        }
        let duration_ms =
            u64::try_from(self.recovery_lease_duration.as_millis()).map_err(|_| {
                EconomicStateRecoveryError::InvalidConfiguration(
                    "recovery lease duration overflowed u64".to_owned(),
                )
            })?;
        let expires_at = trusted_now_unix_ms
            .checked_add(duration_ms)
            .filter(|value| *value <= I_JSON_MAX_SAFE_INTEGER)
            .ok_or_else(|| {
                EconomicStateRecoveryError::InvalidConfiguration(
                    "recovery lease expiry overflowed I-JSON".to_owned(),
                )
            })?;
        self.operations.claim_recovery(
            &operation_id,
            operation.version(),
            &self.claimant_id,
            trusted_now_unix_ms,
            expires_at,
            &self.active_fence,
        )?;
        let Some(revalidated) = self.operations.load_by_operation_id(&operation_id)? else {
            return Ok(false);
        };
        Ok(revalidated == operation)
    }

    fn resolve_uncertain_cas(
        &self,
        stage: EconomicStateStageRecord,
        advance: &VerifiedEconomicStateBatchAdvance,
        trusted_now_unix_ms: u64,
    ) -> Result<EconomicRecoveryOutcome, EconomicStateRecoveryError> {
        let query = state_query(advance.batch());
        let Ok(observed) = self.anchor.read_state(&query) else {
            return Ok(EconomicRecoveryOutcome::Pending(stage));
        };
        if observed.view().checkpoint_sequence == advance.batch().checkpoint_sequence
            && observed.view().checkpoint_digest == advance.batch().checkpoint_digest
        {
            return self.record_and_finalize(advance, &observed, trusted_now_unix_ms);
        }
        if observed.view().checkpoint_sequence > advance.batch().checkpoint_sequence {
            let retained_query = EconomicCheckpointReadQuery {
                checkpoint_sequence: advance.batch().checkpoint_sequence,
                checkpoint_digest: advance.batch().checkpoint_digest.clone(),
                query,
            };
            if let Ok(retained) = self.anchor.read_checkpoint_state(&retained_query) {
                return self.record_and_finalize(advance, &retained, trusted_now_unix_ms);
            }
        }
        Ok(EconomicRecoveryOutcome::Pending(stage))
    }

    fn record_and_finalize(
        &self,
        advance: &VerifiedEconomicStateBatchAdvance,
        committed: &chio_core::economic_continuity::VerifiedEconomicStateView,
        trusted_now_unix_ms: u64,
    ) -> Result<EconomicRecoveryOutcome, EconomicStateRecoveryError> {
        verify_economic_state_batch_commit(advance, committed, &self.pins)?;
        let advanced = self.cache.record_anchor_advanced(
            advance,
            committed,
            &self.pins,
            &self.active_fence,
            trusted_now_unix_ms,
        )?;
        self.finalize(advanced, trusted_now_unix_ms)
    }

    fn finalize(
        &self,
        stage: EconomicStateStageRecord,
        trusted_now_unix_ms: u64,
    ) -> Result<EconomicRecoveryOutcome, EconomicStateRecoveryError> {
        let finalized = self.cache.finalize_stage(
            &stage.batch().batch_id,
            &self.active_fence,
            trusted_now_unix_ms,
        )?;
        Ok(EconomicRecoveryOutcome::Finalized(finalized))
    }

    fn quarantine(
        &self,
        stage: EconomicStateStageRecord,
        reason: &str,
        trusted_now_unix_ms: u64,
    ) -> Result<EconomicRecoveryOutcome, EconomicStateRecoveryError> {
        let quarantined = self.cache.quarantine_stage(
            &stage.batch().batch_id,
            reason,
            &self.active_fence,
            trusted_now_unix_ms,
        )?;
        Ok(EconomicRecoveryOutcome::Quarantined(quarantined))
    }
}

pub struct QualifiedEconomicAdmissionHandoffVerifier {
    operations: Arc<dyn QualifiedAdmissionOperationStore>,
    active_fence: StoreMutationFence,
}

impl QualifiedEconomicAdmissionHandoffVerifier {
    #[must_use]
    pub fn new(
        operations: Arc<dyn QualifiedAdmissionOperationStore>,
        active_fence: StoreMutationFence,
    ) -> Self {
        Self {
            operations,
            active_fence,
        }
    }
}

impl EconomicAdmissionHandoffVerifier for QualifiedEconomicAdmissionHandoffVerifier {
    fn verify_handoff(
        &self,
        operation_id: &str,
        handoff: &EconomicAdmissionHandoffV1,
    ) -> Result<(), EconomicStateAnchorError> {
        handoff.validate()?;
        if handoff.store_fence != self.active_fence {
            return Err(EconomicStateAnchorError::AdmissionHandoffRejected);
        }
        let operation_id = AdmissionOperationId::from_persisted(operation_id.to_owned())
            .map_err(|_| EconomicStateAnchorError::AdmissionHandoffRejected)?;
        let operation = self
            .operations
            .load_by_operation_id(&operation_id)
            .map_err(|_| EconomicStateAnchorError::AdmissionHandoffRejected)?
            .ok_or(EconomicStateAnchorError::AdmissionHandoffRejected)?;
        if operation.version() != handoff.operation_version
            || operation.coordinator_lease_epoch() != handoff.lifecycle_fence
        {
            return Err(EconomicStateAnchorError::AdmissionHandoffRejected);
        }
        let valid = match handoff.state {
            EconomicAdmissionHandoffStateV1::DispatchCommitted => {
                matches!(
                    operation.binding().kind(),
                    AdmissionOperationKind::ToolDispatch
                        | AdmissionOperationKind::GovernedActiveResponse
                ) && operation.state() == AdmissionOperationState::DispatchCommitted
                    && operation.dispatch_commit().is_some_and(|commit| {
                        commit.committed_version == operation.version()
                            && commit.store_fence == self.active_fence
                    })
            }
            EconomicAdmissionHandoffStateV1::MutationSubmitted => {
                operation.binding().kind() == AdmissionOperationKind::GovernedEconomicMutation
                    && operation.state() == AdmissionOperationState::MutationSubmitted
            }
        };
        if valid {
            Ok(())
        } else {
            Err(EconomicStateAnchorError::AdmissionHandoffRejected)
        }
    }
}

fn state_query(
    batch: &chio_core::economic_continuity::EconomicStateBatchV1,
) -> EconomicStateReadQuery {
    EconomicStateReadQuery {
        resource_keys: batch
            .transitions
            .iter()
            .map(|transition| transition.resource_key.clone())
            .collect(),
        request_keys: batch
            .request_replays
            .iter()
            .map(|replay| EconomicRequestKeyV1 {
                request_namespace_digest: replay.request.request_namespace_digest.clone(),
                request_id: replay.request.request_id.clone(),
            })
            .collect(),
    }
}

fn validate_trusted_time(value: u64) -> Result<(), EconomicStateRecoveryError> {
    if value == 0 || value > I_JSON_MAX_SAFE_INTEGER {
        Err(EconomicStateRecoveryError::InvalidConfiguration(
            "trusted recovery time is outside the I-JSON range".to_owned(),
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::collections::VecDeque;
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, MutexGuard};
    use std::time::Duration;
    use std::time::{SystemTime, UNIX_EPOCH};

    use chio_core::crypto::{sha256_hex, Keypair};
    use chio_core::economic_continuity::{
        verify_economic_state_batch_advance, verify_economic_state_view,
        EconomicAdmissionHandoffStateV1, EconomicAdmissionHandoffV1, EconomicContentV1,
        EconomicEffectDispatchCommitV1, EconomicEffectSlotV1, EconomicEffectStateV1,
        EconomicEffectTargetV1, EconomicRequestBindingV1, EconomicResourceHeadV1,
        EconomicResourceKeyV1, EconomicStateAnchor, EconomicStateAnchorError,
        EconomicStateAnchorPins, EconomicStateAnchorViewV1, EconomicStateBatchV1,
        EconomicStateReadQuery, EconomicStateTransitionV1, EconomicTransitionAuthorizationV1,
        EconomicTransitionProofVerifier, VerifiedEconomicEffectDispatch,
        VerifiedEconomicEffectDispatchAdvance, VerifiedEconomicStateBatchAdvance,
        VerifiedEconomicStateView, CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA,
        CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA, CHIO_ECONOMIC_STATE_ANCHOR_VIEW_SCHEMA,
        CHIO_ECONOMIC_STATE_BATCH_SCHEMA,
    };
    use chio_kernel::admission_operation::{
        AdmissionDigest, AdmissionIdentifier, AdmissionOperationBindingInputV1,
        AdmissionOperationBindingV1, AdmissionOperationCommand, AdmissionOperationKind,
        AdmissionOperationStore, AdmissionOperationV1, AdmissionParticipantRequirements,
        AdmissionRequestBindingV1, AuthenticatedRequestNamespace, QualifiedAdmissionOperationStore,
        QualifiedAdmissionOperationStoreExt, SideEffectClass,
    };
    use chio_store_sqlite::{SqliteAuthorityStore, SqliteEconomicStateCache};
    use serde_json::json;
    use tempfile::TempDir;

    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    struct Fixture {
        _temp: TempDir,
        _authority: SqliteAuthorityStore,
        cache: SqliteEconomicStateCache,
        operations: Arc<dyn QualifiedAdmissionOperationStore>,
        fence: StoreMutationFence,
    }

    fn fixture() -> Fixture {
        let temp = tempfile::tempdir().expect("tempdir");
        let database = temp.path().join("authority.db");
        let lock_root = temp.path().join("locks");
        fs::create_dir(&lock_root).expect("create lock root");
        SqliteAuthorityStore::provision(&database, &lock_root).expect("provision authority");
        let authority =
            SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open authority");
        let fence = authority.mutation_fence();
        let cache = authority.economic_state_cache();
        let operations = Arc::new(authority.admission_operation_store());
        Fixture {
            _temp: temp,
            _authority: authority,
            cache,
            operations,
            fence,
        }
    }

    fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        match mutex.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn digest(label: &str) -> String {
        sha256_hex(label.as_bytes())
    }

    fn pins() -> EconomicStateAnchorPins {
        EconomicStateAnchorPins {
            anchor_id: "anchor-1".to_owned(),
            namespace: "economy-prod".to_owned(),
            signer_key_id: "anchor-key-1".to_owned(),
            signer_key_epoch: 1,
            signer_public_key: Keypair::from_seed(&[0x41; 32]).public_key(),
        }
    }

    fn key() -> EconomicResourceKeyV1 {
        EconomicResourceKeyV1 {
            resource_family: "clearing_round".to_owned(),
            scope_id: "market-1".to_owned(),
            resource_id: "round-1".to_owned(),
        }
    }

    fn head() -> TestResult<EconomicResourceHeadV1> {
        let state = EconomicContentV1::Inline {
            value: json!({"roundId": "round-1", "state": "open"}),
        };
        Ok(EconomicResourceHeadV1 {
            schema: CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA.to_owned(),
            anchor_id: "anchor-1".to_owned(),
            namespace: "economy-prod".to_owned(),
            resource_key: key(),
            head_version: 1,
            resource_version: 1,
            lifecycle_fence: 1,
            lifecycle_state: "open".to_owned(),
            state_digest: state.digest()?,
            state,
            operation_id: None,
            effect_idempotency_key: None,
            frost: None,
            terminal_result: None,
            trusted_clock_high_water: 100,
            predecessor_digest: None,
        })
    }

    fn signed_view(
        checkpoint_sequence: u64,
        checkpoint_digest: String,
        heads: Vec<EconomicResourceHeadV1>,
        absent_resource_keys: Vec<EconomicResourceKeyV1>,
    ) -> TestResult<EconomicStateAnchorViewV1> {
        let mut view = EconomicStateAnchorViewV1 {
            schema: CHIO_ECONOMIC_STATE_ANCHOR_VIEW_SCHEMA.to_owned(),
            anchor_id: "anchor-1".to_owned(),
            namespace: "economy-prod".to_owned(),
            checkpoint_sequence,
            checkpoint_digest,
            heads_root: String::new(),
            heads,
            absent_resource_keys,
            request_replays_root: String::new(),
            request_replays: Vec::new(),
            absent_request_keys: Vec::new(),
            observed_at: 100 + checkpoint_sequence,
            signer_key_id: "anchor-key-1".to_owned(),
            signer_key_epoch: 1,
            anchor_signature: String::new(),
        };
        view.seal(&Keypair::from_seed(&[0x41; 32]))?;
        Ok(view)
    }

    #[derive(Debug)]
    struct DirectVerifier;

    impl EconomicTransitionProofVerifier for DirectVerifier {
        fn verify_transition(
            &self,
            _current: Option<&EconomicResourceHeadV1>,
            _transition: &EconomicStateTransitionV1,
        ) -> Result<EconomicTransitionAuthorizationV1, EconomicStateAnchorError> {
            Ok(EconomicTransitionAuthorizationV1::Direct)
        }
    }

    fn verified_advance(
    ) -> TestResult<(VerifiedEconomicStateBatchAdvance, VerifiedEconomicStateView)> {
        verified_advance_for_operation(None)
    }

    fn verified_advance_for_operation(
        operation_id: Option<String>,
    ) -> TestResult<(VerifiedEconomicStateBatchAdvance, VerifiedEconomicStateView)> {
        let resource_head = head()?;
        let current = verify_economic_state_view(
            signed_view(1, digest("checkpoint-1"), Vec::new(), vec![key()])?,
            &pins(),
        )?;
        let mut batch = EconomicStateBatchV1 {
            schema: CHIO_ECONOMIC_STATE_BATCH_SCHEMA.to_owned(),
            batch_id: String::new(),
            checkpoint_digest: String::new(),
            anchor_id: "anchor-1".to_owned(),
            namespace: "economy-prod".to_owned(),
            checkpoint_sequence: 2,
            previous_checkpoint_digest: Some(current.view().checkpoint_digest.clone()),
            expected_heads_root: String::new(),
            next_heads_root: String::new(),
            transitions: vec![EconomicStateTransitionV1 {
                resource_key: key(),
                expected_head_digest: None,
                next_head: resource_head.clone(),
                transition_proof_digest: digest("transition-proof"),
                prepared_effect: None,
            }],
            effect_slots: Vec::new(),
            request_replays: Vec::new(),
            operation_id,
            issued_at: 101,
            signer_key_id: "anchor-key-1".to_owned(),
            signer_key_epoch: 1,
            anchor_signature: String::new(),
        };
        batch.seal(&Keypair::from_seed(&[0x41; 32]))?;
        let advance =
            verify_economic_state_batch_advance(&current, batch, &pins(), &DirectVerifier)?;
        let committed = verify_economic_state_view(
            signed_view(
                2,
                advance.batch().checkpoint_digest.clone(),
                vec![resource_head],
                Vec::new(),
            )?,
            &pins(),
        )?;
        Ok((advance, committed))
    }

    fn identifier(field: &'static str, value: &str) -> AdmissionIdentifier {
        AdmissionIdentifier::try_new(field, value).expect("identifier")
    }

    fn admission_digest(field: &'static str, byte: char) -> AdmissionDigest {
        AdmissionDigest::try_new(field, byte.to_string().repeat(64)).expect("digest")
    }

    fn now_ms() -> u64 {
        u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time")
                .as_millis(),
        )
        .expect("system time fits u64")
    }

    fn prepared_economic_operation(
        fence: &StoreMutationFence,
        request_id: &str,
    ) -> AdmissionOperationV1 {
        let namespace = AuthenticatedRequestNamespace::for_local_system(identifier(
            "coordinator_authority_id",
            "economic-recovery-test",
        ))
        .expect("namespace");
        let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
            kind: AdmissionOperationKind::GovernedEconomicMutation,
            namespace,
            request_id: identifier("request_id", request_id),
            capability_id: identifier("capability_id", "economic-recovery-capability"),
            authorization_capability_hash: admission_digest("authorization_capability_hash", 'a'),
            request_binding: AdmissionRequestBindingV1::new(
                admission_digest("immutable_request_hash", 'b'),
                AdmissionParticipantRequirements::NONE,
            )
            .expect("request binding"),
            policy_hash: admission_digest("policy_hash", 'c'),
            effect_class: SideEffectClass::Monetary,
        })
        .expect("operation binding");
        AdmissionOperationV1::prepare(binding, fence.owner_epoch).expect("prepared operation")
    }

    fn advance_operation(
        operations: &dyn QualifiedAdmissionOperationStore,
        operation: &AdmissionOperationV1,
        claimant: &AdmissionIdentifier,
        fence: &StoreMutationFence,
        next_state: AdmissionOperationState,
        trusted_now_unix_ms: u64,
    ) -> TestResult<AdmissionOperationV1> {
        let lease = operations.claim_recovery(
            operation.binding().operation_id(),
            operation.version(),
            claimant,
            trusted_now_unix_ms,
            trusted_now_unix_ms + 1_000,
            fence,
        )?;
        let command = AdmissionOperationCommand::new(
            operation.binding().operation_id().clone(),
            operation.version(),
            lease,
            Vec::new(),
            Some(next_state),
            None,
            None,
        )?;
        Ok(operations
            .compare_and_swap(&command, trusted_now_unix_ms + 1)?
            .into_operation())
    }

    #[derive(Default)]
    struct FixtureAnchor {
        reads: Mutex<VecDeque<Result<VerifiedEconomicStateView, EconomicStateAnchorError>>>,
        checkpoint_reads:
            Mutex<VecDeque<Result<VerifiedEconomicStateView, EconomicStateAnchorError>>>,
        commits: Mutex<VecDeque<Result<VerifiedEconomicStateView, EconomicStateAnchorError>>>,
        cas_calls: AtomicUsize,
    }

    impl EconomicStateAnchor for FixtureAnchor {
        fn read_state(
            &self,
            _query: &EconomicStateReadQuery,
        ) -> Result<VerifiedEconomicStateView, EconomicStateAnchorError> {
            lock(&self.reads).pop_front().ok_or_else(|| {
                EconomicStateAnchorError::Unavailable("fixture read is missing".to_owned())
            })?
        }

        fn read_checkpoint_state(
            &self,
            _query: &chio_core::economic_continuity::EconomicCheckpointReadQuery,
        ) -> Result<VerifiedEconomicStateView, EconomicStateAnchorError> {
            lock(&self.checkpoint_reads).pop_front().ok_or_else(|| {
                EconomicStateAnchorError::Unavailable(
                    "fixture checkpoint read is missing".to_owned(),
                )
            })?
        }

        fn compare_and_swap_batch(
            &self,
            _advance: &VerifiedEconomicStateBatchAdvance,
        ) -> Result<VerifiedEconomicStateView, EconomicStateAnchorError> {
            self.cas_calls.fetch_add(1, Ordering::SeqCst);
            lock(&self.commits).pop_front().ok_or_else(|| {
                EconomicStateAnchorError::Unavailable("fixture CAS is missing".to_owned())
            })?
        }

        fn compare_and_swap_effect_dispatch(
            &self,
            _advance: VerifiedEconomicEffectDispatchAdvance,
        ) -> Result<VerifiedEconomicEffectDispatch, EconomicStateAnchorError> {
            let _ = core::mem::size_of::<EconomicEffectDispatchCommitV1>();
            Err(EconomicStateAnchorError::Unavailable(
                "effect dispatch is not used by this fixture".to_owned(),
            ))
        }
    }

    fn recovery(fixture: &Fixture, anchor: Arc<FixtureAnchor>) -> EconomicStateRecovery {
        EconomicStateRecovery::new(
            fixture.cache.clone(),
            anchor,
            fixture.operations.clone(),
            Arc::new(DirectVerifier),
            pins(),
            fixture.fence.clone(),
            AdmissionIdentifier::try_new("claimant_id", "economic-recovery").expect("claimant"),
            Duration::from_secs(30),
        )
        .expect("recovery")
    }

    #[test]
    fn unanchored_stage_retries_one_cas_then_finalizes() -> TestResult {
        let fixture = fixture();
        let (advance, committed) = verified_advance()?;
        fixture
            .cache
            .stage_batch(&advance, None, &fixture.fence, 1_000)?;
        let anchor = Arc::new(FixtureAnchor::default());
        lock(&anchor.reads).push_back(Ok(advance.current().clone()));
        lock(&anchor.commits).push_back(Ok(committed));
        let recovery = recovery(&fixture, anchor.clone());

        let outcome = recovery.recover_stage(&advance.batch().batch_id, 1_001)?;
        assert!(matches!(outcome, EconomicRecoveryOutcome::Finalized(_)));
        assert_eq!(anchor.cas_calls.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.cache.load_finalized_head(&key())?, Some(head()?));
        Ok(())
    }

    #[test]
    fn anchored_ahead_recovery_uses_retained_checkpoint_without_replaying_cas() -> TestResult {
        let fixture = fixture();
        let (advance, committed) = verified_advance()?;
        fixture
            .cache
            .stage_batch(&advance, None, &fixture.fence, 1_000)?;
        let ahead = verify_economic_state_view(
            signed_view(3, digest("checkpoint-3"), vec![head()?], Vec::new())?,
            &pins(),
        )?;
        let anchor = Arc::new(FixtureAnchor::default());
        lock(&anchor.reads).push_back(Ok(ahead));
        lock(&anchor.checkpoint_reads).push_back(Ok(committed));
        let recovery = recovery(&fixture, anchor.clone());

        let outcome = recovery.recover_stage(&advance.batch().batch_id, 1_001)?;
        assert!(matches!(outcome, EconomicRecoveryOutcome::Finalized(_)));
        assert_eq!(anchor.cas_calls.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.cache.load_finalized_head(&key())?, Some(head()?));
        Ok(())
    }

    #[test]
    fn operation_version_race_discards_unanchored_stage_without_cas() -> TestResult {
        let fixture = fixture();
        let operations = fixture._authority.admission_operation_store();
        let operation = prepared_economic_operation(&fixture.fence, "operation-race");
        let now = now_ms();
        operations.begin(&operation, &fixture.fence, now)?;
        let stage_claimant = identifier("claimant_id", "stage-owner");
        let stage_lease = operations.claim_recovery(
            operation.binding().operation_id(),
            operation.version(),
            &stage_claimant,
            now + 1,
            now + 1_001,
            &fixture.fence,
        )?;
        let (advance, _) = verified_advance_for_operation(Some(
            operation.binding().operation_id().as_str().to_owned(),
        ))?;
        fixture.cache.stage_batch(
            &advance,
            Some(chio_store_sqlite::EconomicOperationStageContext::new(
                &operation,
                &stage_lease,
            )),
            &fixture.fence,
            now + 2,
        )?;
        advance_operation(
            &operations,
            &operation,
            &stage_claimant,
            &fixture.fence,
            AdmissionOperationState::MutationReady,
            now + 3,
        )?;
        let anchor = Arc::new(FixtureAnchor::default());
        lock(&anchor.reads).push_back(Ok(advance.current().clone()));
        let recovery = recovery(&fixture, anchor.clone());

        let outcome = recovery.recover_stage(&advance.batch().batch_id, now + 5)?;
        assert!(matches!(outcome, EconomicRecoveryOutcome::Discarded(_)));
        assert_eq!(anchor.cas_calls.load(Ordering::SeqCst), 0);
        assert!(fixture.cache.load_finalized_head(&key())?.is_none());
        Ok(())
    }

    #[test]
    fn handoff_verifier_requires_exact_submitted_state_version_and_store_fence() -> TestResult {
        let fixture = fixture();
        let operations = fixture._authority.admission_operation_store();
        let mut operation = prepared_economic_operation(&fixture.fence, "handoff");
        let now = now_ms();
        operations.begin(&operation, &fixture.fence, now)?;
        let claimant = identifier("claimant_id", "handoff-owner");
        operation = advance_operation(
            &operations,
            &operation,
            &claimant,
            &fixture.fence,
            AdmissionOperationState::MutationReady,
            now + 1,
        )?;
        operation = advance_operation(
            &operations,
            &operation,
            &claimant,
            &fixture.fence,
            AdmissionOperationState::MutationSubmitted,
            now + 3,
        )?;
        let verifier = QualifiedEconomicAdmissionHandoffVerifier::new(
            fixture.operations.clone(),
            fixture.fence.clone(),
        );
        let handoff = EconomicAdmissionHandoffV1 {
            state: EconomicAdmissionHandoffStateV1::MutationSubmitted,
            operation_version: operation.version(),
            lifecycle_fence: operation.coordinator_lease_epoch(),
            store_fence: fixture.fence.clone(),
        };

        verifier.verify_handoff(operation.binding().operation_id().as_str(), &handoff)?;
        let mut stale = handoff.clone();
        stale.operation_version -= 1;
        assert!(verifier
            .verify_handoff(operation.binding().operation_id().as_str(), &stale)
            .is_err());
        let mut wrong_lease = handoff;
        wrong_lease.store_fence.lease_id = "different-lease".to_owned();
        assert!(verifier
            .verify_handoff(operation.binding().operation_id().as_str(), &wrong_lease)
            .is_err());
        Ok(())
    }

    struct QualifiedIdempotentTarget;

    impl EconomicIdempotentTargetVerifier for QualifiedIdempotentTarget {
        fn verify_qualification(
            &self,
            target: &EconomicEffectTargetV1,
            idempotency_key: &str,
        ) -> Result<(), EconomicStateAnchorError> {
            if target.qualification_digest == digest("target-qualification")
                && idempotency_key == digest("idempotency-key")
            {
                Ok(())
            } else {
                Err(EconomicStateAnchorError::IdempotentRecoveryRejected)
            }
        }
    }

    struct RejectedIdempotentTarget;

    impl EconomicIdempotentTargetVerifier for RejectedIdempotentTarget {
        fn verify_qualification(
            &self,
            _target: &EconomicEffectTargetV1,
            _idempotency_key: &str,
        ) -> Result<(), EconomicStateAnchorError> {
            Err(EconomicStateAnchorError::IdempotentRecoveryRejected)
        }
    }

    fn committed_effect_slot() -> TestResult<EconomicEffectSlotV1> {
        let mut slot = EconomicEffectSlotV1 {
            schema: CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA.to_owned(),
            slot_id: String::new(),
            anchor_id: "anchor-1".to_owned(),
            namespace: "economy-prod".to_owned(),
            resource_key: key(),
            operation_id: digest("effect-operation"),
            effect_kind: "settlement_dispatch".to_owned(),
            request: EconomicRequestBindingV1 {
                request_namespace_digest: digest("request-namespace"),
                request_id: "request-1".to_owned(),
                request_binding_digest: digest("request-binding"),
            },
            admission_handoff: EconomicAdmissionHandoffV1 {
                state: EconomicAdmissionHandoffStateV1::MutationSubmitted,
                operation_version: 3,
                lifecycle_fence: 1,
                store_fence: StoreMutationFence {
                    store_uuid: "store-1".to_owned(),
                    lease_id: "lease-1".to_owned(),
                    owner_epoch: 1,
                },
            },
            target: EconomicEffectTargetV1 {
                target_id: "settlement-rail".to_owned(),
                target_key_epoch: 1,
                qualification_digest: digest("target-qualification"),
            },
            action_digest: digest("effect-action"),
            parameters_digest: digest("effect-parameters"),
            resource_head_digest: digest("resource-head"),
            frost: None,
            idempotency_key: digest("idempotency-key"),
            state: EconomicEffectStateV1::DispatchCommitted,
            terminal: None,
        };
        slot.slot_id = slot.recompute_slot_id()?;
        slot.validate()?;
        Ok(slot)
    }

    #[test]
    fn committed_effect_recovery_never_returns_invocation_authority_without_qualification(
    ) -> TestResult {
        let slot = committed_effect_slot()?;
        let locked = qualify_committed_effect_recovery(&slot, None, None)?;
        let EconomicEffectRecoveryDecision::LockedUnknown(locked) = locked else {
            return Err("unqualified recovery returned authority".into());
        };
        assert_eq!(locked.next_slot().state, EconomicEffectStateV1::Unknown);

        let rejected =
            qualify_committed_effect_recovery(&slot, None, Some(&RejectedIdempotentTarget))?;
        assert!(matches!(
            rejected,
            EconomicEffectRecoveryDecision::LockedUnknown(_)
        ));
        let qualified =
            qualify_committed_effect_recovery(&slot, None, Some(&QualifiedIdempotentTarget))?;
        assert!(matches!(
            qualified,
            EconomicEffectRecoveryDecision::IdempotentRetry(_)
        ));
        Ok(())
    }
}
