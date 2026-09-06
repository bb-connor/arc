//! Kernel routing of the operation-owned execution nonce participant.
//!
//! A strict preflight owns an internal budget hold, reverses it and retains one
//! signed nonce with the still `Prepared` operation. The execution request
//! presents that nonce; the store reserves and captures it atomically with the
//! same operation. The legacy replay store never sees these nonces.

use super::*;
use crate::admission_operation::{
    AdmissionExecutionNonceReservationV1, AdmissionNoncePreflightHoldDisposition,
    AdmissionNoncePreflightIdentityV1, AdmissionNoncePreflightRecoveryV1,
    AdmissionProjectionCapabilities, RetainedToolAdmissionRequestV1,
};
use crate::budget_store::{
    BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest, BudgetReverseHoldRequest,
};
use crate::execution_nonce::SignedExecutionNonce;

impl DurableToolAdmission {
    pub(crate) fn requires_execution_nonce(&self) -> bool {
        self.operation
            .binding()
            .participant_requirements()
            .execution_nonce
    }

    pub(crate) fn nonce_preflight_identity(
        &self,
        grant_index: usize,
    ) -> Result<AdmissionNoncePreflightIdentityV1, KernelError> {
        let grant_index = u32::try_from(grant_index).map_err(|_| {
            KernelError::DurableAdmission("nonce preflight grant index exceeds u32".to_owned())
        })?;
        AdmissionNoncePreflightIdentityV1::for_operation(&self.operation, grant_index)
            .map_err(KernelError::from)
    }

    pub(crate) fn nonce_preflight(&self) -> Option<&AdmissionNoncePreflightRecoveryV1> {
        self.nonce_preflight.as_ref()
    }

    pub(crate) fn issued_execution_nonce(&self) -> Option<&AdmissionExecutionNonceReservationV1> {
        self.issued_nonce.as_ref()
    }

    fn retained_request(&self) -> Result<&RetainedToolAdmissionRequestV1, KernelError> {
        self.retained_request.as_ref().ok_or_else(|| {
            KernelError::DurableAdmission(
                "nonce operation lost its retained original request".to_owned(),
            )
        })
    }
}

impl ChioKernel {
    /// Decide whether this admission routes execution nonces through the durable
    /// participant. Strict issuance is required: an opt-in nonce profile has no
    /// preflight identity to own, and a store without the participant cannot
    /// retain issuance, so both deny before any operation is begun.
    pub(super) fn durable_nonce_participant_required(
        &self,
        capabilities: &AdmissionProjectionCapabilities,
    ) -> Result<bool, KernelError> {
        let Some(config) = self.execution_nonce_config.as_ref() else {
            return Ok(false);
        };
        if !config.require_nonce {
            return Err(KernelError::DurableAdmission(
                "durable execution nonces require strict issuance".to_owned(),
            ));
        }
        if !capabilities.execution_nonce_participant {
            return Err(KernelError::DurableAdmission(
                "admission store lacks the operation-owned execution nonce participant".to_owned(),
            ));
        }
        Ok(true)
    }

    /// Bind the presented nonce, if any, to the retained operation before any
    /// mutation. A preflight may only continue a `Prepared` operation; an
    /// execution request must present exactly the retained issuance while it is
    /// still live. Returns the verified issuance for execution requests.
    pub(super) fn route_durable_nonce_admission(
        &self,
        operation: &AdmissionOperationV1,
        presented: Option<&SignedExecutionNonce>,
        trusted_now_unix_ms: u64,
    ) -> Result<Option<AdmissionExecutionNonceReservationV1>, KernelError> {
        let Some(presented) = presented else {
            if operation.state() != AdmissionOperationState::Prepared {
                return Err(KernelError::DurableAdmission(format!(
                    "execution nonce preflight cannot replay an operation in state {:?}",
                    operation.state()
                )));
            }
            return Ok(None);
        };
        let issued = self
            .load_durable_nonce_issuance(operation, trusted_now_unix_ms)?
            .ok_or_else(|| {
                KernelError::DurableAdmission(
                    "presented execution nonce was never issued for this request".to_owned(),
                )
            })?;
        if issued.signed_nonce() != presented {
            return Err(KernelError::DurableAdmission(
                "presented execution nonce does not match its retained issuance".to_owned(),
            ));
        }
        // A terminal operation replays its retained result without executing,
        // so the spent nonce no longer needs to be live. Every non-terminal
        // continuation still requires a live nonce before any mutation.
        if !operation.state().is_terminal() {
            require_live_nonce(presented, trusted_now_unix_ms)?;
        }
        Ok(Some(issued))
    }

    pub(super) fn load_durable_nonce_issuance(
        &self,
        operation: &AdmissionOperationV1,
        trusted_now_unix_ms: u64,
    ) -> Result<Option<AdmissionExecutionNonceReservationV1>, KernelError> {
        if operation.execution_nonce_issuance_digest().is_none() {
            return Ok(None);
        }
        let runtime = self.durable_runtime()?;
        runtime
            .store
            .load_execution_nonce_issuance(
                operation.binding().operation_id(),
                &runtime.fence,
                trusted_now_unix_ms,
            )
            .map_err(durable_store_error)
    }

    pub(super) fn load_durable_nonce_preflight(
        &self,
        operation: &AdmissionOperationV1,
        trusted_now_unix_ms: u64,
    ) -> Result<Option<AdmissionNoncePreflightRecoveryV1>, KernelError> {
        if operation.execution_nonce_preflight_digest().is_none() {
            return Ok(None);
        }
        let runtime = self.durable_runtime()?;
        runtime
            .store
            .load_execution_nonce_preflight(
                operation.binding().operation_id(),
                &runtime.fence,
                trusted_now_unix_ms,
            )
            .map_err(durable_store_error)?
            .ok_or_else(|| {
                KernelError::DurableAdmission(
                    "nonce preflight ownership disappeared from the admission store".to_owned(),
                )
            })
            .map(Some)
    }

    /// Whether a `Prepared` operation still waits for its execution request.
    /// Startup recovery leaves such operations alone until the nonce expires.
    pub(super) fn durable_nonce_issuance_is_live(
        &self,
        operation: &AdmissionOperationV1,
        trusted_now_unix_ms: u64,
    ) -> Result<bool, KernelError> {
        if operation.state() != AdmissionOperationState::Prepared
            || !operation
                .binding()
                .participant_requirements()
                .execution_nonce
        {
            return Ok(false);
        }
        Ok(self
            .load_durable_nonce_issuance(operation, trusted_now_unix_ms)?
            .is_some_and(|issued| {
                require_live_nonce(issued.signed_nonce(), trusted_now_unix_ms).is_ok()
            }))
    }

    /// Reserve the internal preflight hold and attach its ownership to the
    /// `Prepared` operation in one store transaction.
    pub(crate) fn authorize_durable_nonce_preflight(
        &self,
        admission: &mut DurableToolAdmission,
        request: BudgetAuthorizeHoldRequest,
        trusted_now_unix_ms: u64,
    ) -> Result<BudgetAuthorizeHoldDecision, KernelError> {
        let runtime = self.durable_runtime()?;
        let _mutation_guard = runtime.lock_mutations()?;
        let trusted_now_unix_ms = runtime.refresh_trusted_time(trusted_now_unix_ms);
        if request.authority.as_ref() != Some(&runtime.authority()) {
            return Err(KernelError::DurableAdmission(
                "nonce preflight authority does not match the admission fence".to_owned(),
            ));
        }
        let expected = admission.operation.clone();
        let recovery_lease = self.claim_admission_recovery(&expected, trusted_now_unix_ms)?;
        let (decision, operation) = runtime
            .store
            .authorize_execution_nonce_preflight(
                &expected,
                &recovery_lease,
                request,
                trusted_now_unix_ms,
            )
            .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
        if operation.binding() != expected.binding()
            || operation.state() != AdmissionOperationState::Prepared
        {
            return Err(KernelError::DurableAdmission(
                "nonce preflight authorization changed the immutable operation".to_owned(),
            ));
        }
        match &decision {
            BudgetAuthorizeHoldDecision::Authorized(_)
            | BudgetAuthorizeHoldDecision::ApprovalRequired(_) => {
                if operation.execution_nonce_preflight_digest().is_none() {
                    return Err(KernelError::DurableAdmission(
                        "nonce preflight authorization returned no ownership".to_owned(),
                    ));
                }
            }
            BudgetAuthorizeHoldDecision::Denied(_) => {
                if operation != expected {
                    return Err(KernelError::DurableAdmission(
                        "denied nonce preflight mutated its operation".to_owned(),
                    ));
                }
            }
            BudgetAuthorizeHoldDecision::AlreadyCaptured(_) => {
                return Err(KernelError::DurableAdmission(
                    "nonce preflight cannot adopt captured budget".to_owned(),
                ));
            }
        }
        admission.operation = operation;
        admission.nonce_preflight =
            self.load_durable_nonce_preflight(&admission.operation, trusted_now_unix_ms)?;
        Ok(decision)
    }

    /// Replay the deterministic cleanup of an owned preflight hold. A hold that
    /// is already reversed needs nothing; a live hold is reversed with the exact
    /// rollback event derived from its authorization commit, so a retry after a
    /// lost acknowledgement cannot create a second reversal.
    pub(crate) fn release_durable_nonce_preflight_hold(
        &self,
        operation: &AdmissionOperationV1,
        recovery: &AdmissionNoncePreflightRecoveryV1,
    ) -> Result<(), KernelError> {
        if recovery.hold() == AdmissionNoncePreflightHoldDisposition::Reversed {
            return Ok(());
        }
        let identity = recovery.identity();
        if identity.parent_operation_id() != operation.binding().operation_id() {
            return Err(KernelError::DurableAdmission(
                "nonce preflight recovery names another operation".to_owned(),
            ));
        }
        let hold_id = identity.hold_id().as_str().to_owned();
        let snapshot = self
            .with_budget_store(|store| Ok(store.get_budget_hold(&hold_id)?))?
            .ok_or_else(|| {
                KernelError::DurableAdmission(
                    "nonce preflight hold is absent from the budget authority".to_owned(),
                )
            })?;
        if snapshot.capability_id != operation.binding().capability_id().as_str()
            || snapshot.grant_index != identity.grant_index() as usize
        {
            return Err(KernelError::DurableAdmission(
                "nonce preflight hold belongs to another grant".to_owned(),
            ));
        }
        if !snapshot.disposition.is_open() {
            return Ok(());
        }
        let authority = self.durable_runtime()?.authority();
        let request = BudgetReverseHoldRequest {
            capability_id: snapshot.capability_id.clone(),
            grant_index: snapshot.grant_index,
            reversed_exposure_units: snapshot.remaining_exposure_units,
            hold_id: Some(hold_id),
            event_id: Some(format!(
                "{}:rollback:{}",
                identity.authorization_event_id().as_str(),
                recovery.authorization_commit_index()
            )),
            expected_cumulative_approval_state: None,
            authority: Some(authority),
        };
        self.with_budget_store(|store| Ok(store.reverse_budget_hold(request)?))?;
        Ok(())
    }

    /// Retain one signed nonce with the `Prepared` operation, or re-deliver the
    /// retained issuance while it is still live. Issuance requires the durable
    /// ownership and physical reversal of the preflight hold; the store rechecks
    /// both inside its transaction.
    pub(crate) fn issue_durable_execution_nonce(
        &self,
        admission: &mut DurableToolAdmission,
        trusted_now_unix_ms: u64,
    ) -> Result<Box<SignedExecutionNonce>, KernelError> {
        let config = self.execution_nonce_config.as_ref().ok_or_else(|| {
            KernelError::DurableAdmission(
                "execution nonce configuration disappeared before issuance".to_owned(),
            )
        })?;
        let runtime = self.durable_runtime()?;
        let _mutation_guard = runtime.lock_mutations()?;
        let trusted_now_unix_ms = runtime.refresh_trusted_time(trusted_now_unix_ms);
        if let Some(issued) =
            self.load_durable_nonce_issuance(&admission.operation, trusted_now_unix_ms)?
        {
            require_live_nonce(issued.signed_nonce(), trusted_now_unix_ms).map_err(|_| {
                KernelError::DurableAdmission(
                    "retained execution nonce expired; retry with a fresh request".to_owned(),
                )
            })?;
            admission.issued_nonce = Some(issued.clone());
            return Ok(Box::new(issued.signed_nonce().clone()));
        }
        if admission.operation.state() != AdmissionOperationState::Prepared {
            return Err(KernelError::DurableAdmission(format!(
                "execution nonce issuance requires a Prepared operation, found {:?}",
                admission.operation.state()
            )));
        }
        let expected = admission.operation.clone();
        let reservation = AdmissionExecutionNonceReservationV1::mint_for_operation(
            &expected,
            admission.retained_request()?,
            &self.config.keypair,
            config,
            trusted_now_unix_ms,
        )
        .map_err(durable_store_error)?;
        let digest = AdmissionDigest::try_new(
            "execution_nonce_issuance_digest",
            sha256_hex(reservation.canonical_bytes()),
        )?;
        let lease = self.claim_admission_recovery(&expected, trusted_now_unix_ms)?;
        let command = AdmissionOperationCommand::new(
            expected.binding().operation_id().clone(),
            expected.version(),
            lease,
            vec![AdmissionAttachment::ExecutionNonceIssuanceDigest(
                digest.clone(),
            )],
            Some(AdmissionOperationState::Prepared),
            None,
            None,
        )?;
        let operation = runtime
            .store
            .issue_execution_nonce_and_commit_admission(&command, &reservation, trusted_now_unix_ms)
            .map_err(durable_store_error)?
            .into_operation();
        if operation.binding() != expected.binding()
            || operation.state() != AdmissionOperationState::Prepared
            || operation.execution_nonce_issuance_digest() != Some(&digest)
        {
            return Err(KernelError::DurableAdmission(
                "execution nonce issuance changed the immutable operation".to_owned(),
            ));
        }
        admission.operation = operation;
        let signed = Box::new(reservation.signed_nonce().clone());
        admission.issued_nonce = Some(reservation);
        Ok(signed)
    }

    /// Reserve the verified nonce with `ReadyToDispatch`, then prepare capture
    /// with `CapturePending`, each atomically with the operation.
    pub(super) fn mark_durable_nonce_capture_pending(
        &self,
        admission: &mut DurableToolAdmission,
        trusted_now_unix_ms: u64,
    ) -> Result<(), KernelError> {
        let issued = admission.issued_nonce.clone().ok_or_else(|| {
            KernelError::DurableAdmission(
                "execution nonce operation reached capture without a verified issuance".to_owned(),
            )
        })?;
        let runtime = self.durable_runtime()?;
        let _mutation_guard = runtime.lock_mutations()?;
        let trusted_now_unix_ms = runtime.refresh_trusted_time(trusted_now_unix_ms);
        if matches!(
            admission.operation.state(),
            AdmissionOperationState::BudgetAuthorized | AdmissionOperationState::ApprovalReserved
        ) {
            let expected = admission.operation.clone();
            let lease = self.claim_admission_recovery(&expected, trusted_now_unix_ms)?;
            let command = AdmissionOperationCommand::new(
                expected.binding().operation_id().clone(),
                expected.version(),
                lease,
                vec![AdmissionAttachment::ExecutionNonceId(
                    issued.nonce_id().clone(),
                )],
                Some(AdmissionOperationState::ReadyToDispatch),
                None,
                None,
            )?;
            let operation = runtime
                .store
                .reserve_execution_nonce_and_commit_admission(
                    &command,
                    &issued,
                    trusted_now_unix_ms,
                )
                .map_err(durable_store_error)?
                .into_operation();
            if operation.binding() != expected.binding()
                || operation.state() != AdmissionOperationState::ReadyToDispatch
                || operation.execution_nonce_id() != Some(issued.nonce_id())
            {
                return Err(KernelError::DurableAdmission(
                    "execution nonce reservation changed the immutable operation".to_owned(),
                ));
            }
            admission.operation = operation;
        }
        if admission.operation.state() == AdmissionOperationState::ReadyToDispatch {
            let expected = admission.operation.clone();
            let lease = self.claim_admission_recovery(&expected, trusted_now_unix_ms)?;
            let command = AdmissionOperationCommand::new(
                expected.binding().operation_id().clone(),
                expected.version(),
                lease,
                Vec::new(),
                Some(AdmissionOperationState::CapturePending),
                None,
                None,
            )?;
            let operation = runtime
                .store
                .begin_execution_nonce_capture(&command, trusted_now_unix_ms)
                .map_err(durable_store_error)?
                .into_operation();
            if operation.binding() != expected.binding()
                || operation.state() != AdmissionOperationState::CapturePending
            {
                return Err(KernelError::DurableAdmission(
                    "execution nonce capture preparation changed the immutable operation"
                        .to_owned(),
                ));
            }
            admission.operation = operation;
        }
        if admission.operation.state() != AdmissionOperationState::CapturePending {
            return Err(KernelError::DurableAdmission(format!(
                "execution nonce capture cannot start from state {:?}",
                admission.operation.state()
            )));
        }
        Ok(())
    }
}

fn require_live_nonce(
    nonce: &SignedExecutionNonce,
    trusted_now_unix_ms: u64,
) -> Result<(), KernelError> {
    let now = i64::try_from(trusted_now_unix_ms / 1_000).unwrap_or(i64::MAX);
    if now >= nonce.expires_at() {
        return Err(KernelError::DurableAdmission(
            "execution nonce expired".to_owned(),
        ));
    }
    Ok(())
}
