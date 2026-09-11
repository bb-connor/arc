//! Configured approval authority and consuming acquisition. Request metadata
//! cannot choose a replay source or manufacture a prepared credential.

use super::governed_approval::{load_exact_history, store_call, validate_recovery_history};
use super::*;
use crate::admission_operation::governed_approval_claim::{
    GovernedApprovalAuthorityBindingV1, GovernedApprovalClaimDisposition as Disposition,
    GovernedApprovalClaimHistoryV1, GovernedApprovalClaimIntentInput,
    GovernedApprovalClaimIntentV1, GovernedApprovalClaimPhase, GovernedApprovalClaimReferenceV1,
    GovernedApprovalCredentialV1,
};
use crate::admission_operation::governed_approval_replay::{
    GovernedApprovalReplaySourcePort, GovernedApprovalReplaySourceSnapshot,
};
use crate::admission_operation::AdmissionRecoveryLease;

pub(crate) struct GovernedApprovalAuthority {
    binding: GovernedApprovalAuthorityBindingV1,
    source: Arc<dyn GovernedApprovalReplaySourcePort>,
}

impl ChioKernel {
    pub(super) fn configured_governed_approval_binding(
        &self,
    ) -> Option<&GovernedApprovalAuthorityBindingV1> {
        self.governed_approval_authority
            .as_ref()
            .map(|authority| &authority.binding)
    }

    /// Install an explicitly activated approval source. This performs no import,
    /// activation or legacy history reset. Once configured, presented single
    /// approvals require operation-owned custody; the legacy store is not used.
    pub fn set_operation_owned_governed_approval_source(
        &mut self,
        binding: GovernedApprovalAuthorityBindingV1,
        source: Arc<dyn GovernedApprovalReplaySourcePort>,
    ) -> Result<(), KernelError> {
        let authority = GovernedApprovalAuthority { binding, source };
        self.verify_governed_approval_source(&authority)?;
        self.governed_approval_authority = Some(authority);
        Ok(())
    }

    pub(crate) fn verify_configured_governed_approval_source(&self) -> Result<(), KernelError> {
        let authority = self
            .governed_approval_authority
            .as_ref()
            .ok_or_else(|| error("operation-owned approval source is not configured"))?;
        self.verify_governed_approval_source(authority).map(|_| ())
    }

    fn verify_governed_approval_source(
        &self,
        authority: &GovernedApprovalAuthority,
    ) -> Result<GovernedApprovalReplaySourceSnapshot, KernelError> {
        let runtime = self.durable_runtime()?;
        let snapshot = {
            let _guard = runtime.lock_mutations()?;
            let now = runtime.refresh_trusted_time(current_unix_timestamp_ms());
            let snapshot = store_call("activation", || {
                runtime.store.load_governed_approval_activation(
                    &authority.binding,
                    &runtime.fence,
                    now,
                )
            })?;
            if snapshot.approval_authority_id()
                != authority.binding.approval_authority_id().as_str()
                || snapshot.destination_authority_id() != runtime.fence.store_uuid
            {
                return Err(error(
                    "approval activation changed its configured authority",
                ));
            }
            snapshot
        };
        // The backend may perform I/O or reenter the destination. Never hold
        // the mutation sequencer while verifying the actual sealed source.
        store_call("source verification", || {
            authority.source.verify_exact(&snapshot)
        })?;
        Ok(snapshot)
    }

    pub(crate) fn claim_prepared_governed_approval(
        &self,
        prepared: super::super::credential_reservation::PreparedDispatchCredentials<'_, '_>,
        admission: &mut DurableToolAdmission,
        grant_index: usize,
        now: u64,
    ) -> Result<(), KernelError> {
        prepared.validate_origin(
            self,
            admission.retained_request.as_ref().ok_or_else(|| {
                error("approval acquisition requires the retained original request")
            })?,
        )?;
        let prepared = prepared.refresh()?;
        let credential = prepared
            .approval_credential()?
            .ok_or_else(|| error("prepared approval credential is missing"))?;
        let authority = self
            .governed_approval_authority
            .as_ref()
            .ok_or_else(|| error("approval authority disappeared before acquisition"))?;
        let phase = acquisition_phase(&admission.operation)?;
        let intent = GovernedApprovalClaimIntentV1::new(GovernedApprovalClaimIntentInput {
            episode_id: AdmissionIdentifier::try_new(
                "approval_episode",
                uuid::Uuid::now_v7().to_string(),
            )?,
            approval_authority_id: authority.binding.approval_authority_id().clone(),
            expectation_id: authority.binding.expectation_id().clone(),
            request_binding_hash: admission.operation.binding().request_binding_hash().clone(),
            grant_index: u32::try_from(grant_index)
                .map_err(|_| error("approval grant index overflow"))?,
            phase,
            credential,
        })
        .map_err(durable_store_error)?;
        let runtime = self.durable_runtime()?;
        let _guard = runtime.lock_mutations()?;
        let now = runtime.refresh_trusted_time(now);
        let lease = self.claim_approval_recovery(&admission.operation, now)?;
        self.release_retained_governed_approval(&admission.operation, &lease, now)?;
        let original = admission.operation.clone();
        let result = store_call("claim", || {
            runtime
                .store
                .claim_governed_approval(&original, &lease, &intent, now)
        });
        if let Ok((updated, _)) = &result {
            if validate_successor(&original, updated, &lease, now).is_ok() {
                admission.operation = updated.clone();
            }
        }
        // A callback can commit and then fail or panic. Always recover the
        // current operation version before the caller attempts compensation.
        let (current, history) = load_history(runtime, &original, now)?;
        admission.operation = current.clone();
        let (updated, reference) = result?;
        validate_successor(&original, &updated, &lease, now)?;
        if updated != current
            || !history.iter().any(|claim| {
                claim.reference == reference
                    && claim.intent == intent
                    && claim.disposition == Disposition::ReservedBeforeDispatch
            })
        {
            return Err(error("approval claim lacks exact live ownership readback"));
        }
        validate_recovery_history(&current, &history)
    }

    pub(crate) fn verify_owned_governed_approval(
        &self,
        admission: &DurableToolAdmission,
        prepared: &super::super::credential_reservation::PreparedDispatchCredentials<'_, '_>,
        credential: &GovernedApprovalCredentialV1,
        grant_index: usize,
    ) -> Result<GovernedApprovalClaimReferenceV1, KernelError> {
        prepared.validate_origin(
            self,
            admission.retained_request.as_ref().ok_or_else(|| {
                error("approval reservation requires the retained original request")
            })?,
        )?;
        let operation = admission.operation();
        let authority = self
            .governed_approval_authority
            .as_ref()
            .ok_or_else(|| error("approval authority is not configured"))?;
        let runtime = self.durable_runtime()?;
        let _guard = runtime.lock_mutations()?;
        let now = runtime.refresh_trusted_time(current_unix_timestamp_ms());
        let history = load_exact_history(runtime, operation, now)?;
        validate_recovery_history(operation, &history)?;
        credential.validate_at(now).map_err(durable_store_error)?;
        if operation.dispatch_commit().is_some() || operation.state().is_terminal() {
            return Err(error(
                "approval credential is past its acquisition boundary",
            ));
        }
        let claim = history
            .iter()
            .find(|claim| {
                claim.disposition == Disposition::ReservedBeforeDispatch
                    && claim.intent.approval_authority_id()
                        == authority.binding.approval_authority_id()
                    && claim.intent.expectation_id() == authority.binding.expectation_id()
                    && usize::try_from(claim.intent.grant_index()).ok() == Some(grant_index)
                    && claim.intent.credential() == credential
                    && claim.intent.phase() == GovernedApprovalClaimPhase::Dispatch
            })
            .ok_or_else(|| {
                error("prepared approval does not match the admitted grant and credential")
            })?;
        Ok(claim.reference.clone())
    }

    pub(crate) fn release_operation_owned_approval_before_dispatch(
        &self,
        operation: Option<&AdmissionOperationV1>,
    ) -> Result<(), KernelError> {
        let Some(operation) =
            operation.filter(|operation| operation.governed_approval_ledger_digest().is_some())
        else {
            return Ok(());
        };
        let runtime = self.durable_runtime()?;
        let _guard = runtime.lock_mutations()?;
        let now = runtime.refresh_trusted_time(current_unix_timestamp_ms());
        let lease = self.claim_approval_recovery(operation, now)?;
        self.release_retained_governed_approval(operation, &lease, now)
    }

    pub(crate) fn release_exact_governed_approval_reservation(
        &self,
        reference: &GovernedApprovalClaimReferenceV1,
    ) -> Result<(), KernelError> {
        let runtime = self.durable_runtime()?;
        let _guard = runtime.lock_mutations()?;
        let now = runtime.refresh_trusted_time(current_unix_timestamp_ms());
        let (operation, mut history) = store_call("reservation history", || {
            runtime.store.load_governed_approval_claim_history(
                reference.operation_id(),
                &runtime.fence,
                now,
            )
        })?
        .ok_or_else(|| error("approval reservation ownership disappeared"))?;
        validate_recovery_history(&operation, &history)?;
        let index = history
            .iter()
            .position(|claim| &claim.reference == reference)
            .ok_or_else(|| error("approval reservation changed its exact reference"))?;
        if history[index].disposition == Disposition::ReleasedBeforeDispatch {
            return Ok(());
        }
        let lease = self.claim_approval_recovery(&operation, now)?;
        store_call("reservation release", || {
            runtime
                .store
                .release_governed_approval(&operation, &lease, reference, now)
        })?;
        history[index].disposition = Disposition::ReleasedBeforeDispatch;
        if load_exact_history(runtime, &operation, now)? != history {
            return Err(error(
                "approval reservation release changed its retained history",
            ));
        }
        Ok(())
    }

    fn claim_approval_recovery(
        &self,
        operation: &AdmissionOperationV1,
        now: u64,
    ) -> Result<AdmissionRecoveryLease, KernelError> {
        // Catch within the sequencer scope, including a lost lease acknowledgement.
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.claim_admission_recovery(operation, now)
        }))
        .unwrap_or_else(|_| Err(error("approval recovery lease callback panicked")))
    }
}

fn acquisition_phase(
    operation: &AdmissionOperationV1,
) -> Result<GovernedApprovalClaimPhase, KernelError> {
    match operation.state() {
        AdmissionOperationState::Prepared
            if operation
                .binding()
                .participant_requirements()
                .execution_nonce
                && operation.execution_nonce_issuance_digest().is_none()
                && operation.execution_nonce_preflight_digest().is_none() =>
        {
            Ok(GovernedApprovalClaimPhase::NoncePreflight)
        }
        AdmissionOperationState::BrokerAttemptRegistered => {
            Ok(GovernedApprovalClaimPhase::Dispatch)
        }
        _ => Err(error(
            "approval claim is outside a selected-grant acquisition episode",
        )),
    }
}

fn load_history(
    runtime: &DurableAdmissionRuntime,
    original: &AdmissionOperationV1,
    now: u64,
) -> Result<(AdmissionOperationV1, Vec<GovernedApprovalClaimHistoryV1>), KernelError> {
    let (current, history) = store_call("claim history", || {
        runtime.store.load_governed_approval_claim_history(
            original.binding().operation_id(),
            &runtime.fence,
            now,
        )
    })?
    .ok_or_else(|| error("approval claim readback is missing"))?;
    if current.binding() != original.binding() || current.version() < original.version() {
        return Err(error(
            "approval readback changed its original operation binding",
        ));
    }
    Ok((current, history))
}

fn validate_successor(
    original: &AdmissionOperationV1,
    updated: &AdmissionOperationV1,
    lease: &AdmissionRecoveryLease,
    now: u64,
) -> Result<(), KernelError> {
    let ledger = updated
        .governed_approval_ledger_digest()
        .ok_or_else(|| error("approval claim omitted its ledger"))?;
    let command = AdmissionOperationCommand::new(
        original.binding().operation_id().clone(),
        original.version(),
        lease.clone(),
        vec![AdmissionAttachment::GovernedApprovalLedgerDigest(
            ledger.clone(),
        )],
        Some(original.state()),
        None,
        None,
    )?;
    if original.apply_command(&command, now)?.into_operation() != *updated {
        return Err(error(
            "approval claim returned an invalid operation successor",
        ));
    }
    Ok(())
}

fn error(reason: &str) -> KernelError {
    KernelError::DurableAdmission(reason.into())
}
