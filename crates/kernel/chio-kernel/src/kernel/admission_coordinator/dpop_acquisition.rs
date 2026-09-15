//! Configured durable DPoP authority and origin-bound credential acquisition.
//! Installing a domain never imports, activates, resets or recreates a source.
use super::dpop_custody::{load_exact_history, store_call, validate_recovery_history};
use super::*;
use crate::admission_operation::dpop_claim::{
    DpopReplayClaimDisposition as Disposition, DpopReplayClaimHistoryV1,
    DpopReplayClaimIntentInputV1, DpopReplayClaimIntentV1, DpopReplayClaimPhase,
    DpopReplayClaimReferenceV1, DpopReplayCredentialV1,
};
use crate::admission_operation::AdmissionRecoveryLease;
use crate::dpop::authority::{
    verify_authority_dpop_proof_stateless, DpopReplayAuthorityV1, VerifiedDpopReplayProof,
};

impl ChioKernel {
    /// Select an independently configured, already activated v2 domain.
    /// This requires the qualified durable runtime. Once installed, this kernel
    /// cannot replace its domain or use the legacy nonce cache for DPoP calls.
    pub fn set_operation_owned_dpop_authority(
        &mut self,
        authority: DpopReplayAuthorityV1,
    ) -> Result<(), KernelError> {
        if self
            .dpop_authority
            .as_ref()
            .is_some_and(|current| current != &authority)
        {
            return Err(error("configured DPoP authority cannot be replaced"));
        }
        self.verify_dpop_activation(&authority)?;
        self.dpop_authority = Some(authority);
        Ok(())
    }

    fn verify_dpop_activation(
        &self,
        authority: &DpopReplayAuthorityV1,
    ) -> Result<u64, KernelError> {
        let runtime = self.durable_runtime()?;
        let _guard = runtime.lock_mutations()?;
        let now = runtime.refresh_trusted_time(current_unix_timestamp_ms());
        let activated = store_call("activation", || {
            runtime
                .store
                .load_dpop_replay_activation(authority, &runtime.fence, now)
        })?;
        if &activated != authority
            || authority.destination_store_uuid().as_str() != runtime.fence.store_uuid
        {
            return Err(error("DPoP activation changed its configured domain"));
        }
        // The retired volatile source is deliberately not consulted here.
        // Its irreversible activation and history belong to the durable store.
        Ok(now)
    }

    pub(crate) fn verify_operation_owned_dpop(
        &self,
        proof: &crate::dpop::DpopProof,
        capability: &CapabilityToken,
        server: &str,
        tool: &str,
        arguments: &serde_json::Value,
    ) -> Result<VerifiedDpopReplayProof, KernelError> {
        let authority = self
            .dpop_authority
            .as_ref()
            .ok_or_else(|| error("operation-owned DPoP authority is not configured"))?;
        let now = self.verify_dpop_activation(authority)?;
        let action =
            canonical_json_bytes(arguments).map_err(|_| error("DPoP action encoding failed"))?;
        verify_authority_dpop_proof_stateless(
            proof,
            capability,
            server,
            tool,
            &sha256_hex(&action),
            authority,
            now / 1000,
        )
    }

    pub(crate) fn claim_prepared_dpop(
        &self,
        prepared: &super::super::credential_reservation::PreparedDispatchCredentials<'_, '_>,
        admission: &mut DurableToolAdmission,
        grant_index: usize,
        now: u64,
    ) -> Result<(), KernelError> {
        prepared.validate_origin(
            self,
            admission
                .retained_request
                .as_ref()
                .ok_or_else(|| error("DPoP acquisition requires the retained original request"))?,
        )?;
        let credential = prepared
            .dpop_credential()
            .cloned()
            .ok_or_else(|| error("prepared DPoP credential is missing"))?;
        let authority = self
            .dpop_authority
            .as_ref()
            .ok_or_else(|| error("DPoP authority disappeared before acquisition"))?;
        if credential.authority() != authority {
            return Err(error("prepared DPoP changed its configured authority"));
        }
        let phase = acquisition_phase(&admission.operation)?;
        let intent = DpopReplayClaimIntentV1::new(DpopReplayClaimIntentInputV1 {
            episode_id: AdmissionIdentifier::try_new(
                "dpop_episode",
                uuid::Uuid::now_v7().to_string(),
            )?,
            request_binding_hash: admission.operation.binding().request_binding_hash().clone(),
            grant_index: u32::try_from(grant_index)
                .map_err(|_| error("DPoP grant index overflow"))?,
            phase,
            credential,
        })
        .map_err(durable_store_error)?;
        let runtime = self.durable_runtime()?;
        let _guard = runtime.lock_mutations()?;
        let now = runtime.refresh_trusted_time(now);
        let lease = self.claim_dpop_recovery(&admission.operation, now)?;
        self.release_retained_dpop(&admission.operation, &lease, now)?;
        let original = admission.operation.clone();
        let result = store_call("claim", || {
            runtime
                .store
                .claim_dpop_replay(&original, &lease, &intent, now)
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
            return Err(error("DPoP claim lacks exact live ownership readback"));
        }
        validate_recovery_history(&current, &history)
    }

    pub(crate) fn verify_owned_dpop(
        &self,
        admission: &DurableToolAdmission,
        prepared: &super::super::credential_reservation::PreparedDispatchCredentials<'_, '_>,
        credential: &DpopReplayCredentialV1,
        grant_index: usize,
    ) -> Result<DpopReplayClaimReferenceV1, KernelError> {
        prepared.validate_origin(
            self,
            admission
                .retained_request
                .as_ref()
                .ok_or_else(|| error("DPoP reservation requires the retained original request"))?,
        )?;
        let operation = admission.operation();
        let authority = self
            .dpop_authority
            .as_ref()
            .ok_or_else(|| error("DPoP authority is not configured"))?;
        let runtime = self.durable_runtime()?;
        let _guard = runtime.lock_mutations()?;
        let now = runtime.refresh_trusted_time(current_unix_timestamp_ms());
        let history = load_exact_history(runtime, operation, now)?;
        validate_recovery_history(operation, &history)?;
        credential.validate_at(now).map_err(durable_store_error)?;
        if operation.dispatch_commit().is_some() || operation.state().is_terminal() {
            return Err(error("DPoP credential is past its acquisition boundary"));
        }
        let claim = history
            .iter()
            .find(|claim| {
                claim.disposition == Disposition::ReservedBeforeDispatch
                    && claim.intent.credential().authority() == authority
                    && usize::try_from(claim.intent.grant_index()).ok() == Some(grant_index)
                    && claim.intent.credential() == credential
                    && claim.intent.phase() == reservation_phase(operation)
            })
            .ok_or_else(|| {
                error("prepared DPoP does not match the admitted grant and credential")
            })?;
        Ok(claim.reference.clone())
    }

    pub(crate) fn release_operation_owned_dpop_before_dispatch(
        &self,
        operation: Option<&AdmissionOperationV1>,
    ) -> Result<(), KernelError> {
        let Some(operation) =
            operation.filter(|operation| operation.dpop_replay_ledger_digest().is_some())
        else {
            return Ok(());
        };
        let runtime = self.durable_runtime()?;
        let _guard = runtime.lock_mutations()?;
        let now = runtime.refresh_trusted_time(current_unix_timestamp_ms());
        let lease = self.claim_dpop_recovery(operation, now)?;
        self.release_retained_dpop(operation, &lease, now)
    }

    pub(crate) fn release_exact_dpop_reservation(
        &self,
        reference: &DpopReplayClaimReferenceV1,
    ) -> Result<(), KernelError> {
        let runtime = self.durable_runtime()?;
        let _guard = runtime.lock_mutations()?;
        let now = runtime.refresh_trusted_time(current_unix_timestamp_ms());
        let (operation, mut history) = store_call("reservation history", || {
            runtime.store.load_dpop_replay_claim_history(
                reference.operation_id(),
                &runtime.fence,
                now,
            )
        })?
        .ok_or_else(|| error("DPoP reservation ownership disappeared"))?;
        validate_recovery_history(&operation, &history)?;
        let index = history
            .iter()
            .position(|claim| &claim.reference == reference)
            .ok_or_else(|| error("DPoP reservation changed its exact reference"))?;
        if history[index].disposition == Disposition::ReleasedBeforeDispatch {
            return Ok(());
        }
        let lease = self.claim_dpop_recovery(&operation, now)?;
        store_call("reservation release", || {
            runtime
                .store
                .release_dpop_replay(&operation, &lease, reference, now)
        })?;
        history[index].disposition = Disposition::ReleasedBeforeDispatch;
        if load_exact_history(runtime, &operation, now)? != history {
            return Err(error(
                "DPoP reservation release changed its retained history",
            ));
        }
        Ok(())
    }

    fn claim_dpop_recovery(
        &self,
        operation: &AdmissionOperationV1,
        now: u64,
    ) -> Result<AdmissionRecoveryLease, KernelError> {
        // Catch within the sequencer scope, including a lost lease acknowledgement.
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.claim_admission_recovery(operation, now)
        }))
        .unwrap_or_else(|_| Err(error("DPoP recovery lease callback panicked")))
    }
}

fn reservation_phase(operation: &AdmissionOperationV1) -> DpopReplayClaimPhase {
    if operation.state() == AdmissionOperationState::Prepared
        && operation.execution_nonce_issuance_digest().is_none()
    {
        DpopReplayClaimPhase::NoncePreflight
    } else {
        DpopReplayClaimPhase::Dispatch
    }
}

fn acquisition_phase(
    operation: &AdmissionOperationV1,
) -> Result<DpopReplayClaimPhase, KernelError> {
    match operation.state() {
        AdmissionOperationState::Prepared
            if operation
                .binding()
                .participant_requirements()
                .execution_nonce
                && operation.execution_nonce_issuance_digest().is_none()
                && operation.execution_nonce_preflight_digest().is_none() =>
        {
            Ok(DpopReplayClaimPhase::NoncePreflight)
        }
        AdmissionOperationState::BrokerAttemptRegistered => Ok(DpopReplayClaimPhase::Dispatch),
        _ => Err(error(
            "DPoP claim is outside a selected-grant acquisition episode",
        )),
    }
}

fn load_history(
    runtime: &DurableAdmissionRuntime,
    original: &AdmissionOperationV1,
    now: u64,
) -> Result<(AdmissionOperationV1, Vec<DpopReplayClaimHistoryV1>), KernelError> {
    let (current, history) = store_call("claim history", || {
        runtime.store.load_dpop_replay_claim_history(
            original.binding().operation_id(),
            &runtime.fence,
            now,
        )
    })?
    .ok_or_else(|| error("DPoP claim readback is missing"))?;
    if current.binding() != original.binding() || current.version() < original.version() {
        return Err(error(
            "DPoP readback changed its original operation binding",
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
        .dpop_replay_ledger_digest()
        .ok_or_else(|| error("DPoP claim omitted its ledger"))?;
    let command = AdmissionOperationCommand::new(
        original.binding().operation_id().clone(),
        original.version(),
        lease.clone(),
        vec![AdmissionAttachment::DpopReplayLedgerDigest(ledger.clone())],
        Some(original.state()),
        None,
        None,
    )?;
    if original.apply_command(&command, now)?.into_operation() != *updated {
        return Err(error("DPoP claim returned an invalid operation successor"));
    }
    Ok(())
}

fn error(reason: &str) -> KernelError {
    KernelError::DurableAdmission(reason.into())
}
