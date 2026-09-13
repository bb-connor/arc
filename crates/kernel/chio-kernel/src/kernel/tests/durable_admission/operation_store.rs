use super::*;
use crate::admission_operation::RetainedToolAdmissionRequestV1;

impl TestAdmissionOperationStore {
    pub(super) fn begin_retained_request(
        &self,
        operation: &AdmissionOperationV1,
        request: &RetainedToolAdmissionRequestV1,
        fence: &StoreMutationFence,
    ) -> Result<AdmissionBeginResult, AdmissionOperationStoreError> {
        self.require_fence(fence)?;
        operation.validate()?;
        request.validate_binding(operation.binding())?;
        let mut state = self.state.lock().expect("test admission state lock");
        let Some(existing) = state.operation.as_ref() else {
            state.operation = Some(operation.clone());
            state.retained_request = Some(request.clone());
            return Ok(AdmissionBeginResult::Created(operation.clone()));
        };
        Ok(match existing.classify_replay(operation) {
            AdmissionReplayClassification::Exact { terminal_replay } => {
                if state
                    .retained_request
                    .as_ref()
                    .is_none_or(|retained| retained.canonical_bytes() != request.canonical_bytes())
                {
                    return Err(AdmissionOperationStoreError::Invariant(
                        "original request is missing or changed".into(),
                    ));
                }
                AdmissionBeginResult::ExactReplay {
                    operation: existing.clone(),
                    terminal_replay,
                }
            }
            AdmissionReplayClassification::Conflict => AdmissionBeginResult::Conflict {
                existing_operation_id: existing.binding().operation_id().clone(),
            },
        })
    }
}

impl AdmissionOperationStore for TestAdmissionOperationStore {
    fn retain_native_dispatch_ledger(
        &self,
        input: crate::admission_operation::NativeSecurityDispatchLedgerContext<'_>,
    ) -> Result<
        crate::admission_operation::NativeSecurityDispatchLedgerRecordV1,
        AdmissionOperationStoreError,
    > {
        self.revalidate_recovery_claim(
            input.custody.operation,
            input.custody.lease.untrusted_claim(),
            input.custody.trusted_now_unix_ms,
            input.custody.lease.store_fence(),
        )?;
        self.native_dispatch_ledger.retain(input)
    }

    fn load_native_dispatch_ledger(
        &self,
        id: &AdmissionOperationId,
        fence: &StoreMutationFence,
        _: u64,
    ) -> Result<
        Option<crate::admission_operation::NativeSecurityDispatchLedgerRecordV1>,
        AdmissionOperationStoreError,
    > {
        self.require_fence(fence)?;
        self.native_dispatch_ledger.load(id)
    }

    fn observe_native_security_flow(
        &self,
        binding: &crate::admission_operation::NativeSecurityAuthorityBindingV1,
        key: &chio_security_types::ports::FlowStateKey,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<
        crate::admission_operation::NativeSecurityFlowObservationV1,
        AdmissionOperationStoreError,
    > {
        self.require_fence(fence)?;
        self.native_egress.observe(binding, key, now)
    }

    fn acquire_native_security_egress(
        &self,
        input: &crate::admission_operation::NativeSecurityEgressContext<'_>,
        command: &chio_security_types::ports::EgressFenceRequest,
    ) -> Result<chio_security_types::ports::EgressFence, AdmissionOperationStoreError> {
        self.native_egress.require_enabled("acquisition")?;
        self.revalidate_recovery_claim(
            input.operation,
            input.lease.untrusted_claim(),
            input.trusted_now_unix_ms,
            input.lease.store_fence(),
        )?;
        self.native_egress.acquire(input, command)
    }

    fn commit_native_security_egress(
        &self,
        input: &crate::admission_operation::NativeSecurityEgressContext<'_>,
        command: &chio_security_types::ports::EgressFenceCommit,
    ) -> Result<chio_security_types::ports::CommittedEgressFence, AdmissionOperationStoreError>
    {
        self.native_egress.require_enabled("commitment")?;
        self.revalidate_recovery_claim(
            input.operation,
            input.lease.untrusted_claim(),
            input.trusted_now_unix_ms,
            input.lease.store_fence(),
        )?;
        self.native_egress.commit(command)
    }

    fn load_native_security_egress(
        &self,
        id: &AdmissionOperationId,
        fence: &StoreMutationFence,
        _: u64,
    ) -> Result<
        Option<(
            AdmissionOperationV1,
            Option<crate::admission_operation::NativeSecurityEgressHistoryV1>,
        )>,
        AdmissionOperationStoreError,
    > {
        self.native_egress.require_enabled("history")?;
        self.require_fence(fence)?;
        self.native_egress.read(self.load_by_operation_id(id)?)
    }

    fn join_native_security_flow(
        &self,
        operation: &AdmissionOperationV1,
        lease: &crate::admission_operation::AdmissionRecoveryLease,
        binding: &crate::admission_operation::NativeSecurityAuthorityBindingV1,
        context: &SecurityInvocationContext,
        command: &chio_security_types::ports::FlowJoinRequest,
        now: u64,
    ) -> Result<chio_security_types::ports::FlowStateSnapshot, AdmissionOperationStoreError> {
        self.revalidate_recovery_claim(
            operation,
            lease.untrusted_claim(),
            now,
            lease.store_fence(),
        )?;
        let retained = self
            .state
            .lock()
            .expect("test state")
            .retained_request
            .clone()
            .expect("original request");
        retained.validate_native_security_context(context)?;
        retained.validate_native_security_authority(binding)?;
        self.native_recovery.join(operation, binding, command)
    }

    fn join_native_security_input(
        &self,
        operation: &AdmissionOperationV1,
        lease: &crate::admission_operation::AdmissionRecoveryLease,
        binding: &crate::admission_operation::NativeSecurityAuthorityBindingV1,
        context: &SecurityInvocationContext,
        input: &crate::admission_operation::NativeSecurityInputJoinRequestV1,
        now: u64,
    ) -> Result<
        crate::admission_operation::NativeSecurityInputJoinRecordV1,
        AdmissionOperationStoreError,
    > {
        self.revalidate_recovery_claim(
            operation,
            lease.untrusted_claim(),
            now,
            lease.store_fence(),
        )?;
        let retained = self
            .state
            .lock()
            .expect("test state")
            .retained_request
            .clone()
            .expect("original request");
        retained.validate_native_security_context(context)?;
        retained.validate_native_security_authority(binding)?;
        self.native_recovery.join_input(operation, binding, input)
    }

    fn load_native_security_input_join(
        &self,
        operation_id: &AdmissionOperationId,
        fence: &StoreMutationFence,
        _: u64,
    ) -> Result<
        Option<(
            AdmissionOperationV1,
            Option<crate::admission_operation::NativeSecurityInputJoinRecordV1>,
        )>,
        AdmissionOperationStoreError,
    > {
        self.require_fence(fence)?;
        self.native_recovery
            .input_history(self.load_by_operation_id(operation_id)?)
    }

    fn load_native_security_flow_join(
        &self,
        operation_id: &AdmissionOperationId,
        fence: &StoreMutationFence,
        _: u64,
    ) -> Result<
        Option<(
            AdmissionOperationV1,
            Option<crate::admission_operation::NativeSecurityFlowJoinRecordV1>,
        )>,
        AdmissionOperationStoreError,
    > {
        self.require_fence(fence)?;
        self.native_recovery
            .history(self.load_by_operation_id(operation_id)?)
    }

    fn load_dpop_replay_activation(
        &self,
        binding: &crate::dpop::authority::DpopReplayAuthorityV1,
        fence: &StoreMutationFence,
        _: u64,
    ) -> Result<crate::dpop::authority::DpopReplayAuthorityV1, AdmissionOperationStoreError> {
        self.require_fence(fence)?;
        self.dpop_recovery.activation(binding)
    }

    fn claim_dpop_replay(
        &self,
        operation: &AdmissionOperationV1,
        lease: &crate::admission_operation::AdmissionRecoveryLease,
        intent: &crate::admission_operation::dpop_claim::DpopReplayClaimIntentV1,
        now: u64,
    ) -> Result<
        (
            AdmissionOperationV1,
            crate::admission_operation::dpop_claim::DpopReplayClaimReferenceV1,
        ),
        AdmissionOperationStoreError,
    > {
        self.revalidate_recovery_claim(
            operation,
            lease.untrusted_claim(),
            now,
            lease.store_fence(),
        )?;
        self.dpop_recovery
            .claim(self, operation, lease, intent, now)
    }

    fn load_dpop_replay_claim_history(
        &self,
        id: &AdmissionOperationId,
        fence: &StoreMutationFence,
        _: u64,
    ) -> Result<
        Option<(
            AdmissionOperationV1,
            Vec<crate::admission_operation::dpop_claim::DpopReplayClaimHistoryV1>,
        )>,
        AdmissionOperationStoreError,
    > {
        self.require_fence(fence)?;
        self.dpop_recovery.history(self.load_by_operation_id(id)?)
    }

    fn release_dpop_replay(
        &self,
        operation: &AdmissionOperationV1,
        lease: &crate::admission_operation::AdmissionRecoveryLease,
        reference: &crate::admission_operation::dpop_claim::DpopReplayClaimReferenceV1,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.revalidate_recovery_claim(
            operation,
            lease.untrusted_claim(),
            now,
            lease.store_fence(),
        )?;
        self.dpop_recovery.release(reference)
    }

    fn load_governed_approval_activation(
        &self,
        binding: &crate::admission_operation::governed_approval_claim::GovernedApprovalAuthorityBindingV1,
        fence: &StoreMutationFence,
        _: u64,
    ) -> Result<
        crate::admission_operation::governed_approval_replay::GovernedApprovalReplaySourceSnapshot,
        AdmissionOperationStoreError,
    > {
        self.require_fence(fence)?;
        self.approval_recovery.activation(binding)
    }

    fn claim_governed_approval(
        &self,
        operation: &AdmissionOperationV1,
        lease: &crate::admission_operation::AdmissionRecoveryLease,
        intent: &crate::admission_operation::governed_approval_claim::GovernedApprovalClaimIntentV1,
        now: u64,
    ) -> Result<
        (
            AdmissionOperationV1,
            crate::admission_operation::governed_approval_claim::GovernedApprovalClaimReferenceV1,
        ),
        AdmissionOperationStoreError,
    > {
        self.revalidate_recovery_claim(
            operation,
            lease.untrusted_claim(),
            now,
            lease.store_fence(),
        )?;
        self.approval_recovery
            .claim(self, operation, lease, intent, now)
    }

    fn load_governed_approval_claim_history(
        &self,
        id: &AdmissionOperationId,
        fence: &StoreMutationFence,
        _: u64,
    ) -> Result<
        Option<(
            AdmissionOperationV1,
            Vec<
                crate::admission_operation::governed_approval_claim::GovernedApprovalClaimHistoryV1,
            >,
        )>,
        AdmissionOperationStoreError,
    > {
        self.require_fence(fence)?;
        self.approval_recovery
            .history(self.load_by_operation_id(id)?)
    }

    fn release_governed_approval(
        &self,
        operation: &AdmissionOperationV1,
        lease: &crate::admission_operation::AdmissionRecoveryLease,
        reference: &crate::admission_operation::governed_approval_claim::GovernedApprovalClaimReferenceV1,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.revalidate_recovery_claim(
            operation,
            lease.untrusted_claim(),
            now,
            lease.store_fence(),
        )?;
        self.approval_recovery.release(reference)
    }

    fn load_runtime_participant_activation(
        &self,
        binding: &crate::admission_operation::runtime_participant::RuntimeParticipantAuthorityBindingV1,
        fence: &StoreMutationFence,
        _trusted_now_unix_ms: u64,
    ) -> Result<
        crate::admission_operation::RuntimeReplaySourceSnapshotV1,
        AdmissionOperationStoreError,
    > {
        self.require_fence(fence)?;
        self.runtime_recovery.activation(binding, fence)
    }

    fn claim_runtime_participants(
        &self,
        operation: &AdmissionOperationV1,
        lease: &crate::admission_operation::AdmissionRecoveryLease,
        intent: &crate::admission_operation::runtime_participant::RuntimeParticipantClaimIntentV1,
        trusted_now_unix_ms: u64,
    ) -> Result<
        (
            AdmissionOperationV1,
            crate::admission_operation::runtime_participant::RuntimeParticipantClaimReferenceV1,
        ),
        AdmissionOperationStoreError,
    > {
        self.revalidate_recovery_claim(
            operation,
            lease.untrusted_claim(),
            trusted_now_unix_ms,
            lease.store_fence(),
        )?;
        self.runtime_recovery
            .claim(self, operation, lease, intent, trusted_now_unix_ms)
    }

    fn load_runtime_participant_history(
        &self,
        operation_id: &AdmissionOperationId,
        fence: &StoreMutationFence,
        _trusted_now_unix_ms: u64,
    ) -> Result<
        Option<(
            AdmissionOperationV1,
            Vec<crate::admission_operation::runtime_participant::RuntimeParticipantClaimHistoryV1>,
        )>,
        AdmissionOperationStoreError,
    > {
        self.require_fence(fence)?;
        self.runtime_recovery
            .load(self.load_by_operation_id(operation_id)?)
    }

    fn release_runtime_participants(
        &self,
        operation: &AdmissionOperationV1,
        lease: &crate::admission_operation::AdmissionRecoveryLease,
        reference: &crate::admission_operation::runtime_participant::RuntimeParticipantClaimReferenceV1,
        trusted_now_unix_ms: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.revalidate_recovery_claim(
            operation,
            lease.untrusted_claim(),
            trusted_now_unix_ms,
            lease.store_fence(),
        )?;
        self.runtime_recovery.release(reference)
    }

    fn begin_with_retained_tool_request(
        &self,
        operation: &AdmissionOperationV1,
        request: &crate::admission_operation::RetainedToolAdmissionRequestV1,
        fence: &StoreMutationFence,
        _trusted_now_unix_ms: u64,
    ) -> Result<AdmissionBeginResult, AdmissionOperationStoreError> {
        self.begin_retained_request(operation, request, fence)
    }

    fn load_retained_tool_request(
        &self,
        operation_id: &AdmissionOperationId,
        fence: &StoreMutationFence,
        _: u64,
    ) -> Result<
        Option<(
            AdmissionOperationV1,
            crate::admission_operation::RetainedToolAdmissionRequestV1,
        )>,
        AdmissionOperationStoreError,
    > {
        self.require_fence(fence)?;
        let state = self.state.lock().expect("test admission state");
        let Some(operation) = state
            .operation
            .as_ref()
            .filter(|operation| operation.binding().operation_id() == operation_id)
        else {
            return Ok(None);
        };
        Ok(state
            .retained_request
            .as_ref()
            .map(|request| (operation.clone(), request.clone())))
    }

    fn begin(
        &self,
        operation: &AdmissionOperationV1,
        fence: &StoreMutationFence,
        _trusted_now_unix_ms: u64,
    ) -> Result<AdmissionBeginResult, AdmissionOperationStoreError> {
        self.require_fence(fence)?;
        operation.validate()?;
        let mut state = self.state.lock().expect("test admission state lock");
        let Some(existing) = state.operation.as_ref() else {
            state.operation = Some(operation.clone());
            return Ok(AdmissionBeginResult::Created(operation.clone()));
        };
        Ok(match existing.classify_replay(operation) {
            AdmissionReplayClassification::Exact { terminal_replay } => {
                AdmissionBeginResult::ExactReplay {
                    operation: existing.clone(),
                    terminal_replay,
                }
            }
            AdmissionReplayClassification::Conflict => AdmissionBeginResult::Conflict {
                existing_operation_id: existing.binding().operation_id().clone(),
            },
        })
    }

    fn load_by_operation_id(
        &self,
        operation_id: &AdmissionOperationId,
    ) -> Result<Option<AdmissionOperationV1>, AdmissionOperationStoreError> {
        self.recovery_lease_faults
            .trip(recovery_lease::Stage::OperationRead);
        Ok(self
            .state
            .lock()
            .expect("test admission state lock")
            .operation
            .as_ref()
            .filter(|operation| operation.binding().operation_id() == operation_id)
            .cloned())
    }

    fn load_by_replay_key(
        &self,
        replay_key: &AdmissionReplayKey,
    ) -> Result<Option<AdmissionOperationV1>, AdmissionOperationStoreError> {
        Ok(self
            .state
            .lock()
            .expect("test admission state lock")
            .operation
            .as_ref()
            .filter(|operation| &operation.replay_key() == replay_key)
            .cloned())
    }

    fn compare_and_swap(
        &self,
        command: &AdmissionOperationCommand,
        trusted_now_unix_ms: u64,
    ) -> Result<AdmissionCommandResult, AdmissionOperationStoreError> {
        let mut state = self.state.lock().expect("test admission state lock");
        let operation = state
            .operation
            .as_ref()
            .filter(|operation| operation.binding().operation_id() == command.operation_id())
            .cloned()
            .ok_or(AdmissionOperationStoreError::NotFound)?;
        let claim = state
            .claim
            .as_ref()
            .filter(|claim| claim.operation_id() == command.operation_id())
            .ok_or(AdmissionOperationStoreError::Fenced)?;
        let lease = command.recovery_lease();
        if claim.claimant_id() != lease.claimant_id()
            || claim.coordinator_lease_id() != lease.coordinator_lease_id()
            || claim.claimed_version() != lease.claimed_version()
            || claim.expires_at_unix_ms() != lease.expires_at_unix_ms()
            || claim.store_fence() != lease.store_fence()
        {
            return Err(AdmissionOperationStoreError::Fenced);
        }
        let result = operation.apply_command(command, trusted_now_unix_ms)?;
        state.operation = Some(result.clone().into_operation());
        state.claim = None;
        Ok(result)
    }

    fn claim_recovery_untrusted(
        &self,
        operation_id: &AdmissionOperationId,
        expected_version: u64,
        claimant_id: &AdmissionIdentifier,
        _trusted_now_unix_ms: u64,
        expires_at_unix_ms: u64,
        fence: &StoreMutationFence,
    ) -> Result<UntrustedAdmissionRecoveryClaim, AdmissionOperationStoreError> {
        self.recovery_lease_faults
            .trip(recovery_lease::Stage::ClaimBefore);
        self.require_fence(fence)?;
        let mut state = self.state.lock().expect("test admission state lock");
        let operation = state
            .operation
            .as_ref()
            .filter(|operation| operation.binding().operation_id() == operation_id)
            .ok_or(AdmissionOperationStoreError::NotFound)?;
        if operation.version() != expected_version {
            return Err(AdmissionOperationError::StaleVersion {
                expected: expected_version,
                actual: operation.version(),
            }
            .into());
        }
        let claim = UntrustedAdmissionRecoveryClaim::new(
            operation_id.clone(),
            claimant_id.clone(),
            AdmissionIdentifier::try_new("coordinator_lease_id", fence.lease_id.clone())?,
            operation.coordinator_lease_epoch(),
            expected_version,
            expires_at_unix_ms,
            fence.clone(),
        )?;
        state.claim = Some(claim.clone());
        drop(state);
        self.recovery_lease_faults
            .trip(recovery_lease::Stage::ClaimAfter);
        Ok(claim)
    }

    fn revalidate_recovery_claim(
        &self,
        operation: &AdmissionOperationV1,
        claim: &UntrustedAdmissionRecoveryClaim,
        trusted_now_unix_ms: u64,
        current_store_fence: &StoreMutationFence,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.recovery_lease_faults
            .trip(recovery_lease::Stage::Revalidate);
        self.require_fence(current_store_fence)?;
        let state = self.state.lock().expect("test admission state lock");
        if state.operation.as_ref() != Some(operation)
            || state.claim.as_ref() != Some(claim)
            || trusted_now_unix_ms >= claim.expires_at_unix_ms()
        {
            return Err(AdmissionOperationStoreError::Fenced);
        }
        Ok(())
    }

    fn list_recoverable(
        &self,
        not_after_unix_ms: u64,
        limit: usize,
    ) -> Result<Vec<AdmissionOperationV1>, AdmissionOperationStoreError> {
        let store_fence = self
            .fence
            .lock()
            .expect("test admission fence lock")
            .clone();
        let state = self.state.lock().expect("test admission state lock");
        // Mirror the durable store's recovery contract: an operation still under a
        // live recovery lease held by the serving fence is being actively driven
        // and is not recoverable. Only an expired lease, a lease from another
        // fence, or no lease at all makes an operation eligible for the sweep.
        Ok(state
            .operation
            .iter()
            .filter(|operation| !operation.state().is_terminal())
            .filter(|operation| {
                operation
                    .parked_approval_deadline_unix_ms()
                    .expect("parked operation retains its proposal")
                    .is_none_or(|deadline| deadline <= not_after_unix_ms)
            })
            .filter(|operation| {
                !state.claim.as_ref().is_some_and(|claim| {
                    claim.operation_id() == operation.binding().operation_id()
                        && claim.expires_at_unix_ms() > not_after_unix_ms
                        && claim.store_fence() == &store_fence
                })
            })
            .take(limit)
            .cloned()
            .collect())
    }

    fn load_terminal_replay(
        &self,
        replay_key: &AdmissionReplayKey,
    ) -> Result<Option<AdmissionTerminalReplay>, AdmissionOperationStoreError> {
        Ok(self
            .load_by_replay_key(replay_key)?
            .and_then(|operation| operation.terminal_replay().cloned()))
    }
}

impl QualifiedAdmissionOperationStore for TestAdmissionOperationStore {}
