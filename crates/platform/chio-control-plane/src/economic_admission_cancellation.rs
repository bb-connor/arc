use std::sync::Arc;
use std::time::Duration;

use chio_core::economic_continuity::{
    EconomicNoEffectKindV1, EconomicStateAnchor, EconomicStateAnchorError,
    VerifiedEconomicEffectCancellationAdvance,
};
use chio_kernel::admission_operation::{
    verified_economic_cancellation_projection, verify_economic_cancellation_terminal_replay,
    AdmissionIdentifier, AdmissionMutationSequencer, AdmissionOperationError, AdmissionOperationId,
    AdmissionOperationState, AdmissionProjectionContext, AdmissionTerminal,
    QualifiedAdmissionOperationStoreExt, StoreMutationFence,
};
use chio_kernel::{QualifiedAdmissionProjectionStore, ReceiptStoreError};

const MAX_CANCELLATION_LEASE_DURATION: Duration = Duration::from_secs(5 * 60);
const I_JSON_MAX_SAFE_INTEGER: u64 = (1_u64 << 53) - 1;

#[derive(Debug, thiserror::Error)]
pub enum EconomicAdmissionCancellationError {
    #[error("economic admission cancellation configuration is invalid: {0}")]
    InvalidConfiguration(String),
    #[error(transparent)]
    AdmissionStore(#[from] chio_kernel::admission_operation::AdmissionOperationStoreError),
    #[error(transparent)]
    Projection(#[from] AdmissionOperationError),
    #[error(transparent)]
    Anchor(#[from] EconomicStateAnchorError),
    #[error(transparent)]
    Receipt(#[from] ReceiptStoreError),
}

pub struct EconomicAdmissionCancellationCoordinator {
    anchor: Arc<dyn EconomicStateAnchor>,
    operations: Arc<dyn QualifiedAdmissionProjectionStore>,
    active_fence: StoreMutationFence,
    claimant_id: AdmissionIdentifier,
    lease_duration: Duration,
    mutation_sequencer: AdmissionMutationSequencer,
}

impl EconomicAdmissionCancellationCoordinator {
    pub fn new(
        anchor: Arc<dyn EconomicStateAnchor>,
        operations: Arc<dyn QualifiedAdmissionProjectionStore>,
        active_fence: StoreMutationFence,
        claimant_id: AdmissionIdentifier,
        lease_duration: Duration,
    ) -> Result<Self, EconomicAdmissionCancellationError> {
        if lease_duration.is_zero() || lease_duration > MAX_CANCELLATION_LEASE_DURATION {
            return Err(EconomicAdmissionCancellationError::InvalidConfiguration(
                "recovery lease duration must be bounded and nonzero".to_owned(),
            ));
        }
        let mutation_sequencer =
            AdmissionMutationSequencer::for_fence(&active_fence).map_err(|error| {
                EconomicAdmissionCancellationError::InvalidConfiguration(error.to_string())
            })?;
        Ok(Self {
            anchor,
            operations,
            active_fence,
            claimant_id,
            lease_duration,
            mutation_sequencer,
        })
    }

    pub fn cancel_after_handoff(
        &self,
        advance: VerifiedEconomicEffectCancellationAdvance,
        trusted_now_unix_ms: u64,
    ) -> Result<AdmissionTerminal, EconomicAdmissionCancellationError> {
        validate_trusted_time(trusted_now_unix_ms)?;
        let operation_id =
            AdmissionOperationId::from_persisted(advance.slot().operation_id.clone())?;
        let expected_terminal = expected_terminal_state(advance.kind())?;
        let _mutation_guard = self.mutation_sequencer.lock().map_err(|error| {
            EconomicAdmissionCancellationError::InvalidConfiguration(error.to_string())
        })?;
        let operation = self
            .operations
            .load_by_operation_id(&operation_id)?
            .ok_or(chio_kernel::admission_operation::AdmissionOperationStoreError::NotFound)?;
        verify_request_binding(&operation, &advance)?;
        if operation.state().is_terminal() {
            if operation.state() != expected_terminal {
                return Err(AdmissionOperationError::TerminalProjectionBindingMismatch.into());
            }
            verify_economic_cancellation_terminal_replay(&operation, &advance)?;
            let replay = operation
                .terminal_replay()
                .cloned()
                .ok_or(AdmissionOperationError::TerminalReplayMismatch)?;
            return Ok(AdmissionTerminal {
                operation_id,
                state: expected_terminal,
                replay,
            });
        }
        let lease_ms = u64::try_from(self.lease_duration.as_millis()).map_err(|_| {
            EconomicAdmissionCancellationError::InvalidConfiguration(
                "recovery lease duration overflowed u64".to_owned(),
            )
        })?;
        let expires_at_unix_ms = trusted_now_unix_ms
            .checked_add(lease_ms)
            .filter(|value| *value <= I_JSON_MAX_SAFE_INTEGER)
            .ok_or_else(|| {
                EconomicAdmissionCancellationError::InvalidConfiguration(
                    "recovery lease expiry overflowed I-JSON".to_owned(),
                )
            })?;
        let lease = self.operations.claim_recovery(
            &operation_id,
            operation.version(),
            &self.claimant_id,
            trusted_now_unix_ms,
            expires_at_unix_ms,
            &self.active_fence,
        )?;
        let context = AdmissionProjectionContext {
            operation_id: operation_id.clone(),
            request_id: operation.replay_key().request_id,
            expected_operation_version: operation.version(),
            trusted_time_unix_ms: trusted_now_unix_ms,
            coordinator_lease_id: lease.coordinator_lease_id().clone(),
            coordinator_lease_epoch: operation.coordinator_lease_epoch(),
            store_fence: self.active_fence.clone(),
        };
        let cancellation = self.anchor.compare_and_swap_effect_cancellation(advance)?;
        let projection =
            verified_economic_cancellation_projection(&operation, context, &cancellation)?;
        let terminal = self.operations.commit_admission_projection(&projection)?;
        if terminal.operation_id != operation_id || terminal.state != expected_terminal {
            return Err(AdmissionOperationError::TerminalProjectionBindingMismatch.into());
        }
        Ok(terminal)
    }
}

fn expected_terminal_state(
    kind: EconomicNoEffectKindV1,
) -> Result<AdmissionOperationState, EconomicAdmissionCancellationError> {
    match kind {
        EconomicNoEffectKindV1::VerifiedTransportNotAccepted => {
            Ok(AdmissionOperationState::NotAcceptedAfterDispatchCommit)
        }
        EconomicNoEffectKindV1::PermanentlyNotApplied => {
            Ok(AdmissionOperationState::EconomicMutationNotApplied)
        }
        EconomicNoEffectKindV1::PreDispatch => {
            Err(AdmissionOperationError::TerminalProjectionBindingMismatch.into())
        }
    }
}

fn verify_request_binding(
    operation: &chio_kernel::admission_operation::AdmissionOperationV1,
    advance: &VerifiedEconomicEffectCancellationAdvance,
) -> Result<(), EconomicAdmissionCancellationError> {
    let slot = advance.slot();
    if slot.operation_id != operation.binding().operation_id().as_str()
        || slot.request.request_namespace_digest
            != operation.replay_key().request_namespace_digest.as_str()
        || slot.request.request_id != operation.replay_key().request_id.as_str()
        || slot.request.request_binding_digest
            != operation.binding().request_binding_hash().as_str()
    {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch.into());
    }
    Ok(())
}

fn validate_trusted_time(value: u64) -> Result<(), EconomicAdmissionCancellationError> {
    if value == 0 || value > I_JSON_MAX_SAFE_INTEGER {
        Err(EconomicAdmissionCancellationError::InvalidConfiguration(
            "trusted cancellation time is outside the I-JSON range".to_owned(),
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::fs;
    use std::sync::{Arc, Mutex, MutexGuard};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use chio_core::crypto::{sha256_hex, Keypair};
    use chio_core::economic_continuity::{
        verify_economic_effect_cancellation_advance, verify_economic_effect_cancellation_commit,
        verify_economic_state_batch_advance, verify_economic_state_view,
        EconomicAdmissionHandoffStateV1, EconomicAdmissionHandoffV1,
        EconomicAdmissionHandoffVerifier, EconomicContentV1,
        EconomicEffectCancellationProofVerifier, EconomicEffectDispatchCommitV1,
        EconomicEffectSlotV1, EconomicEffectStateV1, EconomicEffectTargetV1,
        EconomicEffectTerminalV1, EconomicNoEffectKindV1, EconomicRequestBindingV1,
        EconomicResourceHeadV1, EconomicResourceKeyV1, EconomicStateAnchor,
        EconomicStateAnchorError, EconomicStateAnchorPins, EconomicStateAnchorViewV1,
        EconomicStateBatchV1, EconomicStateReadQuery, EconomicStateTransitionV1,
        EconomicTransitionAuthorizationV1, EconomicTransitionProofVerifier,
        VerifiedEconomicEffectCancellationAdvance, VerifiedEconomicEffectDispatch,
        VerifiedEconomicEffectDispatchAdvance, VerifiedEconomicEffectNotDispatched,
        VerifiedEconomicStateBatchAdvance, VerifiedEconomicStateView,
        CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA, CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA,
        CHIO_ECONOMIC_STATE_ANCHOR_VIEW_SCHEMA, CHIO_ECONOMIC_STATE_BATCH_SCHEMA,
    };
    use chio_kernel::admission_operation::{
        AdmissionDigest, AdmissionIdentifier, AdmissionOperationBindingInputV1,
        AdmissionOperationBindingV1, AdmissionOperationCommand, AdmissionOperationKind,
        AdmissionOperationState, AdmissionOperationStore, AdmissionOperationV1,
        AdmissionParticipantRequirements, AdmissionRequestBindingV1, AuthenticatedRequestNamespace,
        QualifiedAdmissionOperationStoreExt, SideEffectClass, StoreMutationFence,
    };
    use chio_store_sqlite::SqliteAuthorityStore;
    use serde_json::json;

    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        match mutex.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn digest(label: &str) -> String {
        sha256_hex(label.as_bytes())
    }

    fn id(field: &'static str, value: &str) -> AdmissionIdentifier {
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
        .expect("time fits u64")
    }

    fn submitted_operation(fence: &StoreMutationFence) -> AdmissionOperationV1 {
        let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
            kind: AdmissionOperationKind::GovernedEconomicMutation,
            namespace: AuthenticatedRequestNamespace::for_local_system(id(
                "coordinator_authority_id",
                "economic-cancellation-test",
            ))
            .expect("namespace"),
            request_id: id("request_id", "mutation-cancellation"),
            capability_id: id("capability_id", "mutation-capability"),
            authorization_capability_hash: admission_digest("authorization_hash", 'a'),
            request_binding: AdmissionRequestBindingV1::new(
                admission_digest("request_hash", 'b'),
                AdmissionParticipantRequirements::NONE,
            )
            .expect("request binding"),
            policy_hash: admission_digest("policy_hash", 'c'),
            effect_class: SideEffectClass::Monetary,
        })
        .expect("binding");
        AdmissionOperationV1::prepare(binding, fence.owner_epoch).expect("operation")
    }

    fn advance_operation(
        store: &chio_store_sqlite::SqliteAdmissionOperationStore,
        operation: &AdmissionOperationV1,
        fence: &StoreMutationFence,
        state: AdmissionOperationState,
        now: u64,
    ) -> TestResult<AdmissionOperationV1> {
        let lease = store.claim_recovery(
            operation.binding().operation_id(),
            operation.version(),
            &id("claimant_id", "setup"),
            now,
            now + 1_000,
            fence,
        )?;
        let command = AdmissionOperationCommand::new(
            operation.binding().operation_id().clone(),
            operation.version(),
            lease,
            Vec::new(),
            Some(state),
            None,
            None,
        )?;
        Ok(store.compare_and_swap(&command, now + 1)?.into_operation())
    }

    #[derive(Debug)]
    struct Direct;

    impl EconomicTransitionProofVerifier for Direct {
        fn verify_transition(
            &self,
            _current: Option<&EconomicResourceHeadV1>,
            _transition: &EconomicStateTransitionV1,
        ) -> Result<EconomicTransitionAuthorizationV1, EconomicStateAnchorError> {
            Ok(EconomicTransitionAuthorizationV1::Direct)
        }
    }

    impl EconomicAdmissionHandoffVerifier for Direct {
        fn verify_operation_active(
            &self,
            _operation_id: &str,
        ) -> Result<(), EconomicStateAnchorError> {
            Ok(())
        }

        fn verify_handoff(
            &self,
            _operation_id: &str,
            _handoff: &EconomicAdmissionHandoffV1,
        ) -> Result<(), EconomicStateAnchorError> {
            Ok(())
        }
    }

    impl EconomicEffectCancellationProofVerifier for Direct {
        fn verify_cancellation(
            &self,
            _current: &EconomicEffectSlotV1,
            _next: &EconomicEffectSlotV1,
        ) -> Result<EconomicNoEffectKindV1, EconomicStateAnchorError> {
            Ok(EconomicNoEffectKindV1::PermanentlyNotApplied)
        }
    }

    fn pins(keypair: &Keypair) -> EconomicStateAnchorPins {
        EconomicStateAnchorPins {
            anchor_id: "anchor-1".to_owned(),
            namespace: "economy-prod".to_owned(),
            signer_key_id: "anchor-key-1".to_owned(),
            signer_key_epoch: 1,
            signer_public_key: keypair.public_key(),
        }
    }

    fn signed_view(
        keypair: &Keypair,
        sequence: u64,
        checkpoint_digest: String,
        head: EconomicResourceHeadV1,
    ) -> TestResult<EconomicStateAnchorViewV1> {
        let mut view = EconomicStateAnchorViewV1 {
            schema: CHIO_ECONOMIC_STATE_ANCHOR_VIEW_SCHEMA.to_owned(),
            anchor_id: "anchor-1".to_owned(),
            namespace: "economy-prod".to_owned(),
            checkpoint_sequence: sequence,
            checkpoint_digest,
            heads_root: String::new(),
            heads: vec![head],
            absent_resource_keys: Vec::new(),
            request_replays_root: String::new(),
            request_replays: Vec::new(),
            absent_request_keys: Vec::new(),
            observed_at: 100 + sequence,
            signer_key_id: "anchor-key-1".to_owned(),
            signer_key_epoch: 1,
            anchor_signature: String::new(),
        };
        view.seal(keypair)?;
        Ok(view)
    }

    fn effect_head(
        slot: &EconomicEffectSlotV1,
        version: u64,
        predecessor_digest: Option<String>,
    ) -> TestResult<EconomicResourceHeadV1> {
        let state = EconomicContentV1::Inline {
            value: serde_json::to_value(slot)?,
        };
        Ok(EconomicResourceHeadV1 {
            schema: CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA.to_owned(),
            anchor_id: slot.anchor_id.clone(),
            namespace: slot.namespace.clone(),
            resource_key: slot.resource_head_key(),
            head_version: version,
            resource_version: version,
            lifecycle_fence: version,
            lifecycle_state: match slot.state {
                EconomicEffectStateV1::Ready => "ready",
                EconomicEffectStateV1::NoEffect => "no_effect",
                _ => "invalid",
            }
            .to_owned(),
            state_digest: state.digest()?,
            state,
            operation_id: Some(slot.operation_id.clone()),
            effect_idempotency_key: Some(slot.idempotency_key.clone()),
            frost: None,
            terminal_result: None,
            trusted_clock_high_water: 100 + version,
            predecessor_digest,
        })
    }

    fn cancellation_pair(
        operation: &AdmissionOperationV1,
        fence: &StoreMutationFence,
        suffix: &str,
    ) -> TestResult<(
        VerifiedEconomicEffectCancellationAdvance,
        VerifiedEconomicEffectNotDispatched,
    )> {
        let keypair = Keypair::from_seed(&[0x63; 32]);
        let pins = pins(&keypair);
        let mut slot = EconomicEffectSlotV1 {
            schema: CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA.to_owned(),
            slot_id: String::new(),
            anchor_id: pins.anchor_id.clone(),
            namespace: pins.namespace.clone(),
            resource_key: EconomicResourceKeyV1 {
                resource_family: "clearing_round".to_owned(),
                scope_id: "market-1".to_owned(),
                resource_id: format!("round-{suffix}"),
            },
            operation_id: operation.binding().operation_id().as_str().to_owned(),
            effect_kind: "clearing_finalize".to_owned(),
            request: EconomicRequestBindingV1 {
                request_namespace_digest: operation
                    .replay_key()
                    .request_namespace_digest
                    .as_str()
                    .to_owned(),
                request_id: operation.replay_key().request_id.as_str().to_owned(),
                request_binding_digest: operation
                    .binding()
                    .request_binding_hash()
                    .as_str()
                    .to_owned(),
            },
            admission_handoff: EconomicAdmissionHandoffV1 {
                state: EconomicAdmissionHandoffStateV1::MutationSubmitted,
                operation_version: operation.version(),
                lifecycle_fence: operation.coordinator_lease_epoch(),
                store_fence: fence.clone(),
            },
            target: EconomicEffectTargetV1 {
                target_id: "clearing-engine".to_owned(),
                target_key_epoch: 1,
                qualification_digest: digest("target-qualification"),
            },
            action_digest: digest(&format!("action-{suffix}")),
            parameters_digest: digest(&format!("parameters-{suffix}")),
            resource_head_digest: digest(&format!("resource-head-{suffix}")),
            frost: None,
            idempotency_key: digest(&format!("idempotency-{suffix}")),
            state: EconomicEffectStateV1::Ready,
            terminal: None,
        };
        slot.slot_id = slot.recompute_slot_id()?;
        let ready_head = effect_head(&slot, 1, None)?;
        let ready_digest = ready_head.digest()?;
        let raw_current = signed_view(&keypair, 1, digest("checkpoint-1"), ready_head)?;
        let proof = EconomicContentV1::Inline {
            value: json!({"permanentlyNotApplied": true}),
        };
        slot.state = EconomicEffectStateV1::NoEffect;
        slot.terminal = Some(EconomicEffectTerminalV1::NoEffect {
            kind: EconomicNoEffectKindV1::PermanentlyNotApplied,
            proof_id: format!("mutation-cancellation-proof-{suffix}"),
            proof_digest: proof.digest()?,
            proof,
        });
        let cancelled_head = effect_head(&slot, 2, Some(ready_digest.clone()))?;
        let current = verify_economic_state_view(raw_current.clone(), &pins)?;
        let mut batch = EconomicStateBatchV1 {
            schema: CHIO_ECONOMIC_STATE_BATCH_SCHEMA.to_owned(),
            batch_id: String::new(),
            checkpoint_digest: String::new(),
            anchor_id: pins.anchor_id.clone(),
            namespace: pins.namespace.clone(),
            checkpoint_sequence: 2,
            previous_checkpoint_digest: Some(current.view().checkpoint_digest.clone()),
            expected_heads_root: String::new(),
            next_heads_root: String::new(),
            transitions: vec![EconomicStateTransitionV1 {
                resource_key: cancelled_head.resource_key.clone(),
                expected_head_digest: Some(ready_digest),
                next_head: cancelled_head.clone(),
                transition_proof_digest: digest("transition-proof"),
                prepared_effect: None,
            }],
            effect_slots: Vec::new(),
            request_replays: Vec::new(),
            operation_id: Some(slot.operation_id.clone()),
            issued_at: 102,
            signer_key_id: pins.signer_key_id.clone(),
            signer_key_epoch: pins.signer_key_epoch,
            anchor_signature: String::new(),
        };
        batch.seal(&keypair)?;
        let committed_raw =
            signed_view(&keypair, 2, batch.checkpoint_digest.clone(), cancelled_head)?;
        let coordinator_advance = verify_economic_effect_cancellation_advance(
            verify_economic_state_batch_advance(&current, batch.clone(), &pins, &Direct)?,
            &Direct,
            &Direct,
        )?;
        let authority_advance = verify_economic_effect_cancellation_advance(
            verify_economic_state_batch_advance(
                &verify_economic_state_view(raw_current, &pins)?,
                batch,
                &pins,
                &Direct,
            )?,
            &Direct,
            &Direct,
        )?;
        let committed = verify_economic_state_view(committed_raw, &pins)?;
        let authority =
            verify_economic_effect_cancellation_commit(authority_advance, &committed, &pins)?;
        Ok((coordinator_advance, authority))
    }

    struct CancellationAnchor {
        batch_id: String,
        authority: Mutex<Option<VerifiedEconomicEffectNotDispatched>>,
    }

    impl EconomicStateAnchor for CancellationAnchor {
        fn read_state(
            &self,
            _query: &EconomicStateReadQuery,
        ) -> Result<VerifiedEconomicStateView, EconomicStateAnchorError> {
            Err(EconomicStateAnchorError::Unavailable("unused".to_owned()))
        }

        fn read_checkpoint_state(
            &self,
            _query: &chio_core::economic_continuity::EconomicCheckpointReadQuery,
        ) -> Result<VerifiedEconomicStateView, EconomicStateAnchorError> {
            Err(EconomicStateAnchorError::Unavailable("unused".to_owned()))
        }

        fn compare_and_swap_batch(
            &self,
            _advance: &VerifiedEconomicStateBatchAdvance,
        ) -> Result<VerifiedEconomicStateView, EconomicStateAnchorError> {
            Err(EconomicStateAnchorError::Unavailable("unused".to_owned()))
        }

        fn compare_and_swap_effect_dispatch(
            &self,
            _advance: VerifiedEconomicEffectDispatchAdvance,
        ) -> Result<VerifiedEconomicEffectDispatch, EconomicStateAnchorError> {
            let _ = core::mem::size_of::<EconomicEffectDispatchCommitV1>();
            Err(EconomicStateAnchorError::Unavailable("unused".to_owned()))
        }

        fn compare_and_swap_effect_cancellation(
            &self,
            advance: VerifiedEconomicEffectCancellationAdvance,
        ) -> Result<VerifiedEconomicEffectNotDispatched, EconomicStateAnchorError> {
            if advance.batch().batch_id != self.batch_id {
                return Err(EconomicStateAnchorError::EffectCancellationRejected(
                    "wrong batch",
                ));
            }
            lock(&self.authority).take().ok_or_else(|| {
                EconomicStateAnchorError::Unavailable("authority already consumed".to_owned())
            })
        }
    }

    #[test]
    fn cancellation_coordinator_commits_the_external_and_local_terminal_lifecycle() -> TestResult {
        let temp = tempfile::tempdir()?;
        let database = temp.path().join("authority.db");
        let lock_root = temp.path().join("locks");
        fs::create_dir(&lock_root)?;
        SqliteAuthorityStore::provision(&database, &lock_root)?;
        let authority_store = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
        let fence = authority_store.mutation_fence();
        let store = authority_store.admission_operation_store();
        let now = now_ms();
        let prepared = submitted_operation(&fence);
        store.begin(&prepared, &fence, now)?;
        let ready = advance_operation(
            &store,
            &prepared,
            &fence,
            AdmissionOperationState::MutationReady,
            now + 1,
        )?;
        let submitted = advance_operation(
            &store,
            &ready,
            &fence,
            AdmissionOperationState::MutationSubmitted,
            now + 3,
        )?;
        let (advance, cancellation) = cancellation_pair(&submitted, &fence, "1")?;
        let (replay_advance, _) = cancellation_pair(&submitted, &fence, "1")?;
        let batch_id = advance.batch().batch_id.clone();
        let anchor = Arc::new(CancellationAnchor {
            batch_id,
            authority: Mutex::new(Some(cancellation)),
        });
        let store = Arc::new(store);
        let coordinator = EconomicAdmissionCancellationCoordinator::new(
            anchor,
            store.clone(),
            fence,
            id("claimant_id", "economic-cancellation"),
            Duration::from_secs(30),
        )?;

        let terminal = coordinator.cancel_after_handoff(advance, now + 2_000)?;
        assert_eq!(
            terminal.state,
            AdmissionOperationState::EconomicMutationNotApplied
        );
        let persisted = store
            .load_by_operation_id(submitted.binding().operation_id())?
            .ok_or("terminal operation missing")?;
        assert_eq!(
            persisted.state(),
            AdmissionOperationState::EconomicMutationNotApplied
        );
        let replay = coordinator.cancel_after_handoff(replay_advance, now + 2_001)?;
        assert_eq!(replay, terminal);
        Ok(())
    }

    #[test]
    fn terminal_replay_rejects_a_sibling_effect_cancellation() -> TestResult {
        let temp = tempfile::tempdir()?;
        let database = temp.path().join("authority.db");
        let lock_root = temp.path().join("locks");
        fs::create_dir(&lock_root)?;
        SqliteAuthorityStore::provision(&database, &lock_root)?;
        let authority_store = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
        let fence = authority_store.mutation_fence();
        let store = authority_store.admission_operation_store();
        let now = now_ms();
        let prepared = submitted_operation(&fence);
        store.begin(&prepared, &fence, now)?;
        let ready = advance_operation(
            &store,
            &prepared,
            &fence,
            AdmissionOperationState::MutationReady,
            now + 1,
        )?;
        let submitted = advance_operation(
            &store,
            &ready,
            &fence,
            AdmissionOperationState::MutationSubmitted,
            now + 3,
        )?;
        let (first_advance, first_cancellation) = cancellation_pair(&submitted, &fence, "1")?;
        let (sibling_advance, _) = cancellation_pair(&submitted, &fence, "2")?;
        let anchor = Arc::new(CancellationAnchor {
            batch_id: first_advance.batch().batch_id.clone(),
            authority: Mutex::new(Some(first_cancellation)),
        });
        let coordinator = EconomicAdmissionCancellationCoordinator::new(
            anchor,
            Arc::new(store),
            fence,
            id("claimant_id", "economic-cancellation"),
            Duration::from_secs(30),
        )?;

        coordinator.cancel_after_handoff(first_advance, now + 2_000)?;
        let error = coordinator
            .cancel_after_handoff(sibling_advance, now + 2_001)
            .expect_err("a sibling effect must not replay another slot's terminal projection");
        assert!(matches!(
            error,
            EconomicAdmissionCancellationError::Projection(
                AdmissionOperationError::TerminalProjectionBindingMismatch
            )
        ));
        Ok(())
    }
}
