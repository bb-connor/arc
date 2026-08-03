use crate::security_admission_operation::{
    AdmissionCleanupAction, AdmissionCleanupActionKind, AdmissionCleanupActionState,
    AdmissionDispatchState, AdmissionOperation, AdmissionOperationKind, AdmissionOperationState,
    ReplayReservationState,
};
use chio_core::{canonical_json_bytes, sha256, Hash, PublicKey};
use chio_security_types::ports::{
    Digest32, PreparedActiveResponseDispatchBinding, RecordId, ResponseDispatchApproval,
    PREPARED_ACTIVE_RESPONSE_DISPATCH_BINDING_SCHEMA_VERSION,
    RESPONSE_DISPATCH_AUTHORIZATION_SCHEMA_VERSION,
};
use chio_security_types::{
    ResponseExecutionDispatchBinding, ResponseMutationRecord, ResponsePlan, ResponseSnapshot,
    ResponseState, ResponseTransitionCause, RESPONSE_STATE_SCHEMA_VERSION,
};

use super::active_response_coordinator::{
    active_response_denied, build_active_response_execution_request,
    validate_executable_response_plan_value, ActiveResponseDispatchPermit,
    GovernedActiveResponseReservation, PreparedActiveResponseAdmission,
    VerifiedActiveResponseAdmission,
};
use super::active_response_operation_binding::{
    active_response_dispatch_operation_version, build_active_response_operation_anchor,
    derive_active_response_operation_request_binding_hash,
};
use super::{
    derive_active_response_dispatch_id, ActiveResponseCommittedDispatch,
    ActiveResponseExecutionApproval, ActiveResponseExecutionEvidence,
    ActiveResponseExecutionRequest, ActiveResponseExecutionRequestParts,
    ActiveResponseExecutorAuthorityIdentity, ActiveResponseExecutorError,
    AutomaticActiveResponseDispatchFenceOutcome, ChioKernel, KernelError,
};

#[derive(Debug)]
pub enum DispatchCommittedActiveResponseResume {
    NotDispatchCommitted,
    Completed(Box<ActiveResponseExecutionEvidence>),
}

#[derive(Debug)]
pub enum PreDispatchActiveResponseReconstruction {
    NotPrepared,
    Prepared(PreparedActiveResponseAdmission),
}

impl PreparedActiveResponseAdmission {
    pub fn durable_dispatch_binding(
        &self,
        response_plan: &ResponsePlan,
    ) -> Result<PreparedActiveResponseDispatchBinding, KernelError> {
        validate_executable_response_plan_value(response_plan)?;
        let (
            dispatch_id,
            executor_authority_id,
            executor_authority_generation,
            authorized_at_unix_ms,
            authorization_capability_hash,
            governed_intent_hash,
            policy_decision_hash,
            approval,
        ) = match self {
            Self::Automatic(permit) => {
                if permit.request_id != response_plan.action_id.as_str()
                    || permit.plan_body_hash != digest_hex(&response_plan.plan_hash)
                    || permit.expires_at_unix_ms != response_plan.expires_at_unix_ms
                {
                    return Err(never_committed_denied(
                        "automatic preparation does not match the durable response plan",
                    ));
                }
                (
                    permit.dispatch_id.clone(),
                    permit.executor_authority_id.clone(),
                    permit.executor_authority_generation,
                    permit.authorized_at_unix_ms,
                    permit.authorization_capability_hash.clone(),
                    permit.governed_intent_hash.clone(),
                    permit.policy_decision_hash.clone(),
                    ResponseDispatchApproval::Automatic,
                )
            }
            Self::Governed(reservation) => {
                let operation = &reservation.operation;
                let expected_request_binding_hash =
                    derive_active_response_operation_request_binding_hash(
                        &digest_hex(&response_plan.plan_hash),
                        &reservation.executor_authority_id,
                        reservation.executor_authority_generation,
                        &reservation.authorization_capability_hash,
                        &reservation.governed_intent_hash,
                        reservation.approval_set.approval_set_hash(),
                        &digest_hex(&response_plan.policy_hash),
                    )?;
                if operation.kind() != AdmissionOperationKind::GovernedActiveResponse
                    || operation.request_id() != response_plan.action_id.as_str()
                    || operation.coordinator_authority_id() != reservation.executor_authority_id
                    || operation.authorization_capability_hash()
                        != reservation.authorization_capability_hash
                    || operation.policy_hash() != digest_hex(&response_plan.policy_hash)
                    || operation.approval_set_hash()
                        != Some(reservation.approval_set.approval_set_hash())
                    || operation.request_binding_hash() != expected_request_binding_hash
                    || active_response_dispatch_operation_version(operation)?
                        != reservation.dispatch_operation_version
                {
                    return Err(never_committed_denied(
                        "governed preparation does not match the durable response plan",
                    ));
                }
                (
                    reservation.dispatch_id.clone(),
                    reservation.executor_authority_id.clone(),
                    reservation.executor_authority_generation,
                    reservation.authorized_at_unix_ms,
                    reservation.authorization_capability_hash.clone(),
                    reservation.governed_intent_hash.clone(),
                    reservation.policy_decision_hash.clone(),
                    ResponseDispatchApproval::Governed {
                        admission_operation_id: RecordId::new(operation.operation_id().to_string())
                            .map_err(|error| {
                                never_committed_internal(format!(
                                    "prepared admission operation identifier is invalid: {error}"
                                ))
                            })?,
                        admission_operation_version: reservation.dispatch_operation_version,
                        approval_set_hash: digest_from_hex(
                            reservation.approval_set.approval_set_hash(),
                            "approval set",
                        )?,
                    },
                )
            }
        };
        let binding = PreparedActiveResponseDispatchBinding {
            schema_version: PREPARED_ACTIVE_RESPONSE_DISPATCH_BINDING_SCHEMA_VERSION,
            tenant_id: response_plan.tenant_id.clone(),
            action_id: response_plan.action_id.clone(),
            plan_hash: response_plan.plan_hash,
            dispatch_id,
            executor_authority_id: RecordId::new(executor_authority_id).map_err(|error| {
                never_committed_internal(format!(
                    "prepared executor authority identifier is invalid: {error}"
                ))
            })?,
            executor_authority_generation,
            authorized_at_unix_ms,
            authorization_capability_hash: digest_from_hex(
                &authorization_capability_hash,
                "authorization capability",
            )?,
            governed_intent_hash: digest_from_hex(&governed_intent_hash, "governed intent")?,
            policy_decision_hash: digest_from_hex(&policy_decision_hash, "policy decision")?,
            approval,
        };
        validate_prepared_binding(response_plan, &binding)?;
        Ok(binding)
    }
}

impl ChioKernel {
    /// Reconstruct one retained preparation from an exact durable commitment,
    /// or require full live verification while it remains pre-dispatch.
    pub fn reconstruct_pre_dispatch_active_response_admission(
        &self,
        request: &super::ActiveResponseAdmissionRequest,
        binding: &PreparedActiveResponseDispatchBinding,
    ) -> Result<PreDispatchActiveResponseReconstruction, KernelError> {
        let response_plan = request.response_plan();
        validate_executable_response_plan_value(response_plan)?;
        let (expected_executor, _) = validate_prepared_binding(response_plan, binding)?;
        if let ResponseDispatchApproval::Governed {
            admission_operation_id,
            admission_operation_version,
            approval_set_hash,
        } = &binding.approval
        {
            let operation_store = self.admission_operation_store.as_ref().ok_or_else(|| {
                never_committed_internal("durable admission operation store is not installed")
            })?;
            let Some(operation) = operation_store
                .load(admission_operation_id.as_str())
                .map_err(|error| {
                    never_committed_internal(format!(
                        "prepared admission operation lookup failed: {error}"
                    ))
                })?
            else {
                return Ok(PreDispatchActiveResponseReconstruction::NotPrepared);
            };
            validate_durable_governed_operation_binding(
                self,
                response_plan,
                binding,
                &operation,
                admission_operation_id,
                *admission_operation_version,
                approval_set_hash,
            )?;
            if let Some(committed) = self.reconcile_governed_active_response_commit(
                operation_store.as_ref(),
                self.approval_store.as_deref(),
                &operation,
            )? {
                if matches!(
                    committed.state(),
                    AdmissionOperationState::DispatchCommitted | AdmissionOperationState::Completed
                ) {
                    return Ok(PreDispatchActiveResponseReconstruction::NotPrepared);
                }
            }
        }
        let verified = self.verify_active_response_admission_with_authorized_at(
            request,
            super::current_unix_timestamp_ms(),
            binding.authorized_at_unix_ms,
        )?;
        let preflight = match &verified {
            VerifiedActiveResponseAdmission::Automatic(permit) => {
                PreparedActiveResponseAdmission::Automatic(permit.clone())
            }
            VerifiedActiveResponseAdmission::Governed(verified) => {
                let dispatch_operation_version =
                    active_response_dispatch_operation_version(&verified.operation)?;
                let approval = ActiveResponseExecutionApproval::Governed {
                    admission_operation_id: verified.operation.operation_id().to_string(),
                    admission_operation_version: dispatch_operation_version,
                    approval_set_hash: verified.approval_set.approval_set_hash().to_string(),
                };
                let execution = build_active_response_execution_request(
                    request,
                    expected_executor.clone(),
                    &verified.policy_decision_hash,
                    verified.authorized_at_unix_ms,
                    approval,
                )?;
                PreparedActiveResponseAdmission::Governed(GovernedActiveResponseReservation {
                    operation: verified.operation.clone(),
                    approval_set: verified.approval_set.clone(),
                    policy_decision_hash: verified.policy_decision_hash.clone(),
                    authorization_capability_hash: execution
                        .authorization_capability_hash()
                        .to_string(),
                    governed_intent_hash: execution.governed_intent_hash().to_string(),
                    executor_authority_id: execution.executor_authority_id().to_string(),
                    executor_authority_generation: execution.executor_authority_generation(),
                    authorized_at_unix_ms: execution.authorized_at_unix_ms(),
                    dispatch_operation_version,
                    dispatch_id: execution.dispatch_id().clone(),
                })
            }
        };
        if &preflight.durable_dispatch_binding(response_plan)? != binding {
            return Err(never_committed_denied(
                "live admission does not match the retained prepared dispatch",
            ));
        }
        if let VerifiedActiveResponseAdmission::Governed(verified) = &verified {
            let operation_store = self.admission_operation_store.as_ref().ok_or_else(|| {
                never_committed_internal("durable admission operation store is not installed")
            })?;
            let operation = operation_store
                .load(verified.operation.operation_id())
                .map_err(|error| {
                    never_committed_internal(format!(
                        "prepared admission operation lookup failed: {error}"
                    ))
                })?;
            let Some(operation) = operation else {
                return Ok(PreDispatchActiveResponseReconstruction::NotPrepared);
            };
            let ResponseDispatchApproval::Governed {
                admission_operation_id,
                admission_operation_version,
                approval_set_hash,
            } = &binding.approval
            else {
                return Err(never_committed_denied(
                    "governed live admission has an automatic durable binding",
                ));
            };
            validate_durable_governed_operation_binding(
                self,
                response_plan,
                binding,
                &operation,
                admission_operation_id,
                *admission_operation_version,
                approval_set_hash,
            )?;
        }
        let prepared = self.prepare_verified_active_response_admission(request, verified)?;
        if &prepared.durable_dispatch_binding(response_plan)? != binding {
            return Err(never_committed_internal(
                "persisted preparation diverged after exact live preflight",
            ));
        }
        let crossed_dispatch_commit = matches!(
            &prepared,
            PreparedActiveResponseAdmission::Governed(reservation)
                if matches!(
                    reservation.operation.state(),
                    AdmissionOperationState::DispatchCommitted | AdmissionOperationState::Completed
                )
        );
        if crossed_dispatch_commit {
            Ok(PreDispatchActiveResponseReconstruction::NotPrepared)
        } else {
            Ok(PreDispatchActiveResponseReconstruction::Prepared(prepared))
        }
    }

    /// Recover only an exact dispatch already retained by the installed
    /// executor's durable commit store.
    ///
    /// `Ok(None)` means that no tenant-scoped durable dispatch exists. Callers
    /// must then use the ordinary live admission path, including governed
    /// pre-dispatch cleanup. A malformed or mismatched durable record fails
    /// closed and is never reported as missing.
    pub fn recover_committed_active_response(
        &self,
        response_plan: &ResponsePlan,
        dispatch_id: &RecordId,
    ) -> Result<Option<ActiveResponseExecutionEvidence>, KernelError> {
        validate_executable_response_plan_value(response_plan)?;
        let installed = self.active_response_executor.as_ref().ok_or_else(|| {
            committed_recovery_internal("active-response executor authority is not installed")
        })?;
        installed
            .authority
            .ensure_ready()
            .map_err(map_executor_lookup_error)?;
        if installed.authority.identity() != installed.identity {
            return Err(committed_recovery_denied(
                "active-response executor authority identity is stale",
            ));
        }
        let Some(committed) = installed
            .authority
            .load_committed_active_response_dispatch(&response_plan.tenant_id, dispatch_id)
            .map_err(map_executor_lookup_error)?
        else {
            return Ok(None);
        };
        if installed.authority.identity() != installed.identity {
            return Err(committed_recovery_internal(
                "active-response executor authority identity changed during durable readback",
            ));
        }

        let execution = validate_committed_dispatch(
            response_plan,
            dispatch_id,
            &installed.identity,
            &committed,
        )?;
        let governed_permit = self.validate_committed_governed_operation(&execution)?;
        let evidence = self.execute_active_response_with_authority(&execution)?;
        if let Some(permit) = governed_permit.as_ref() {
            self.complete_active_response_dispatch(permit, &execution, &evidence)?;
        }
        Ok(Some(evidence))
    }

    /// Resume an irreversible governed admission commitment that may have
    /// crashed before the executor durably committed the exact dispatch.
    pub fn resume_dispatch_committed_active_response(
        &self,
        response_plan: &ResponsePlan,
        binding: &PreparedActiveResponseDispatchBinding,
    ) -> Result<DispatchCommittedActiveResponseResume, KernelError> {
        validate_executable_response_plan_value(response_plan)?;
        let (expected_executor, execution_approval) =
            validate_prepared_binding(response_plan, binding)?;
        let installed = self.active_response_executor.as_ref().ok_or_else(|| {
            committed_resume_internal("active-response executor authority is not installed")
        })?;
        let _dispatch_gate = installed.dispatch_gate.lock().map_err(|_| {
            committed_resume_internal("active-response executor dispatch gate is poisoned")
        })?;
        installed
            .authority
            .ensure_ready()
            .map_err(map_executor_lookup_error)?;
        if installed.identity != expected_executor
            || installed.authority.identity() != installed.identity
        {
            return Err(committed_resume_denied(
                "installed executor authority does not match the durable binding",
            ));
        }
        let ActiveResponseExecutionApproval::Governed {
            admission_operation_id,
            admission_operation_version,
            approval_set_hash,
        } = &execution_approval
        else {
            return Ok(DispatchCommittedActiveResponseResume::NotDispatchCommitted);
        };

        let admission_operation_id =
            RecordId::new(admission_operation_id.clone()).map_err(|error| {
                committed_resume_denied(format!(
                    "governed admission operation identifier is invalid: {error}"
                ))
            })?;
        let approval_set_hash_digest = digest_from_hex(approval_set_hash, "approval set")?;
        let mut operation = self.load_active_response_operation(admission_operation_id.as_str())?;
        validate_durable_governed_operation_binding(
            self,
            response_plan,
            binding,
            &operation,
            &admission_operation_id,
            *admission_operation_version,
            &approval_set_hash_digest,
        )?;
        let operation_store = self.admission_operation_store.as_ref().ok_or_else(|| {
            committed_resume_internal("durable admission operation store is not installed")
        })?;
        if let Some(reconciled) = self.reconcile_governed_active_response_commit(
            operation_store.as_ref(),
            self.approval_store.as_deref(),
            &operation,
        )? {
            operation = reconciled;
        }
        match operation.state() {
            AdmissionOperationState::Prepared
            | AdmissionOperationState::ApprovalReserved
            | AdmissionOperationState::CompensatedBeforeDispatch => {
                return Ok(DispatchCommittedActiveResponseResume::NotDispatchCommitted)
            }
            AdmissionOperationState::CompensationPending => {
                if !self.recover_compensated_admission_operation(operation.operation_id())? {
                    return Err(committed_resume_internal(
                        "active-response compensation cleanup is owned by another worker",
                    ));
                }
                return Ok(DispatchCommittedActiveResponseResume::NotDispatchCommitted);
            }
            AdmissionOperationState::DispatchCommitted
                if operation.dispatch_state() == AdmissionDispatchState::Committed => {}
            AdmissionOperationState::Completed
                if operation.dispatch_state() == AdmissionDispatchState::EffectCompleted => {}
            _ => {
                return Err(committed_resume_denied(
                    "durable governed operation has an invalid committed state",
                ))
            }
        }

        let approval_store = self
            .approval_store
            .as_ref()
            .ok_or_else(|| committed_resume_internal("durable approval store is not installed"))?;
        let approval = approval_store
            .get_approval_reservation(admission_operation_id.as_str())
            .map_err(|error| {
                committed_resume_internal(format!(
                    "durable approval reservation lookup failed: {error}"
                ))
            })?
            .ok_or_else(|| committed_resume_internal("durable approval reservation is missing"))?;
        if approval.operation_id() != admission_operation_id.as_str()
            || approval.approval_set().approval_set_hash() != approval_set_hash
        {
            return Err(committed_resume_denied(
                "durable approval reservation does not match the committed operation",
            ));
        }
        let approval_input = approval.approval_set().clone();
        match (operation.state(), approval.state()) {
            (AdmissionOperationState::DispatchCommitted, ReplayReservationState::Reserved) => {
                self.commit_active_response_approval_set(
                    admission_operation_id.as_str(),
                    &approval_input,
                )?;
            }
            (
                AdmissionOperationState::DispatchCommitted | AdmissionOperationState::Completed,
                ReplayReservationState::Committed,
            ) => {}
            _ => {
                return Err(committed_resume_denied(
                    "durable approval reservation is not resumably committed",
                ))
            }
        }
        let committed_approval = approval_store
            .get_approval_reservation(admission_operation_id.as_str())
            .map_err(|error| {
                committed_resume_internal(format!(
                    "committed approval reservation lookup failed: {error}"
                ))
            })?
            .ok_or_else(|| {
                committed_resume_internal("committed approval reservation is missing")
            })?;
        if committed_approval.operation_id() != admission_operation_id.as_str()
            || committed_approval.approval_set() != &approval_input
            || committed_approval.state() != ReplayReservationState::Committed
        {
            return Err(committed_resume_denied(
                "approval reservation did not converge to the exact commitment",
            ));
        }

        let committed = installed
            .authority
            .load_committed_active_response_dispatch(&binding.tenant_id, &binding.dispatch_id)
            .map_err(map_executor_lookup_error)?;
        if installed.authority.identity() != installed.identity {
            return Err(committed_resume_internal(
                "executor authority identity changed during durable readback",
            ));
        }
        if let Some(committed) = committed {
            let execution = validate_committed_dispatch(
                response_plan,
                &binding.dispatch_id,
                &installed.identity,
                &committed,
            )?;
            let permit = self
                .validate_committed_governed_operation(&execution)?
                .ok_or_else(|| {
                    committed_resume_internal(
                        "committed governed dispatch resolved to automatic approval",
                    )
                })?;
            let evidence = self.execute_active_response_with_authority(&execution)?;
            self.complete_active_response_dispatch(&permit, &execution, &evidence)?;
            return Ok(DispatchCommittedActiveResponseResume::Completed(Box::new(
                evidence,
            )));
        }
        if operation.state() == AdmissionOperationState::Completed {
            return Err(committed_resume_internal(
                "completed governed operation lacks its executor dispatch record",
            ));
        }

        let execution = execution_request_from_prepared_binding(
            response_plan,
            binding,
            expected_executor,
            execution_approval,
            true,
        );
        let permit = ActiveResponseDispatchPermit {
            operation,
            recovery: true,
        };
        let evidence = self.execute_active_response_with_authority(&execution)?;
        self.complete_active_response_dispatch(&permit, &execution, &evidence)?;
        Ok(DispatchCommittedActiveResponseResume::Completed(Box::new(
            evidence,
        )))
    }

    /// Close one exact prepared dispatch only after the installed executor's
    /// tenant-scoped durable store proves that it never committed.
    pub fn terminate_never_committed_active_response(
        &self,
        response_plan: &ResponsePlan,
        binding: &PreparedActiveResponseDispatchBinding,
        current_request: Option<&super::ActiveResponseAdmissionRequest>,
    ) -> Result<(), KernelError> {
        validate_executable_response_plan_value(response_plan)?;
        let (expected_executor, _) = validate_prepared_binding(response_plan, binding)?;
        let installed = self.active_response_executor.as_ref().ok_or_else(|| {
            never_committed_internal("active-response executor authority is not installed")
        })?;
        let _dispatch_gate = installed.dispatch_gate.lock().map_err(|_| {
            never_committed_internal("active-response executor dispatch gate is poisoned")
        })?;
        if super::current_unix_timestamp_ms() < response_plan.expires_at_unix_ms {
            let request = current_request.ok_or_else(|| {
                never_committed_denied(
                    "an exact current admission request is required before plan expiry",
                )
            })?;
            if request.response_plan() != response_plan {
                return Err(never_committed_denied(
                    "current admission request does not match the prepared response plan",
                ));
            }
            self.require_definitive_active_response_denial(request)?;
        }
        installed
            .authority
            .ensure_ready()
            .map_err(map_executor_lookup_error)?;
        if installed.identity != expected_executor
            || installed.authority.identity() != installed.identity
        {
            return Err(never_committed_denied(
                "installed executor authority does not match the prepared dispatch",
            ));
        }
        match &binding.approval {
            ResponseDispatchApproval::Automatic => {
                let outcome = installed
                    .authority
                    .fence_uncommitted_automatic_dispatch(response_plan, binding)
                    .map_err(map_automatic_dispatch_fence_error)?;
                if installed.authority.identity() != installed.identity {
                    return Err(never_committed_internal(
                        "executor authority identity changed during durable dispatch fencing",
                    ));
                }
                match outcome {
                    AutomaticActiveResponseDispatchFenceOutcome::Fenced => Ok(()),
                    AutomaticActiveResponseDispatchFenceOutcome::DispatchCommitted => {
                        Err(never_committed_denied(
                            "durable executor fencing found a committed dispatch",
                        ))
                    }
                }
            }
            ResponseDispatchApproval::Governed {
                admission_operation_id,
                admission_operation_version,
                approval_set_hash,
            } => {
                if installed
                    .authority
                    .load_committed_active_response_dispatch(
                        &binding.tenant_id,
                        &binding.dispatch_id,
                    )
                    .map_err(map_executor_lookup_error)?
                    .is_some()
                {
                    return Err(never_committed_denied(
                        "durable executor readback found a committed dispatch",
                    ));
                }
                if installed.authority.identity() != installed.identity {
                    return Err(never_committed_internal(
                        "executor authority identity changed during durable readback",
                    ));
                }
                self.terminate_never_committed_governed_operation(
                    response_plan,
                    binding,
                    admission_operation_id,
                    *admission_operation_version,
                    approval_set_hash,
                )?;
                if installed
                    .authority
                    .load_committed_active_response_dispatch(
                        &binding.tenant_id,
                        &binding.dispatch_id,
                    )
                    .map_err(map_executor_lookup_error)?
                    .is_some()
                {
                    return Err(never_committed_internal(
                        "active-response dispatch committed during pre-dispatch termination",
                    ));
                }
                if installed.authority.identity() != installed.identity {
                    return Err(never_committed_internal(
                        "executor authority identity changed during pre-dispatch termination",
                    ));
                }
                Ok(())
            }
        }
    }

    fn terminate_never_committed_governed_operation(
        &self,
        response_plan: &ResponsePlan,
        binding: &PreparedActiveResponseDispatchBinding,
        admission_operation_id: &RecordId,
        admission_operation_version: u64,
        approval_set_hash: &Digest32,
    ) -> Result<(), KernelError> {
        let operation_id = admission_operation_id.as_str();
        let mut operation = self.load_active_response_operation(operation_id)?;
        validate_durable_governed_operation_binding(
            self,
            response_plan,
            binding,
            &operation,
            admission_operation_id,
            admission_operation_version,
            approval_set_hash,
        )?;
        let operation_store = self.admission_operation_store.as_ref().ok_or_else(|| {
            never_committed_internal("durable admission operation store is not installed")
        })?;
        let approval_store = self
            .approval_store
            .as_ref()
            .ok_or_else(|| never_committed_internal("durable approval store is not installed"))?;
        let approval_set_hash_hex = digest_hex(approval_set_hash);
        let approval_before = approval_store
            .get_approval_reservation(operation_id)
            .map_err(|error| {
                never_committed_internal(format!(
                    "prepared approval reservation lookup failed: {error}"
                ))
            })?;
        if approval_before.as_ref().is_some_and(|reservation| {
            reservation.operation_id() != operation_id
                || reservation.approval_set().approval_set_hash() != approval_set_hash_hex.as_str()
                || !matches!(
                    reservation.state(),
                    ReplayReservationState::Reserved | ReplayReservationState::Cancelled
                )
        }) || (operation.state() == AdmissionOperationState::ApprovalReserved
            && !approval_before
                .as_ref()
                .is_some_and(|reservation| reservation.state() == ReplayReservationState::Reserved))
        {
            return Err(never_committed_denied(
                "durable approval reservation does not match the prepared dispatch",
            ));
        }
        validate_approval_cleanup_actions(
            operation_store
                .load_cleanup_actions(operation_id)
                .map_err(|error| {
                    never_committed_internal(format!(
                        "prepared cleanup journal lookup failed: {error}"
                    ))
                })?,
            &operation,
            false,
        )?;

        for _ in 0..8 {
            match operation.state() {
                AdmissionOperationState::Prepared | AdmissionOperationState::ApprovalReserved => {
                    operation = self.stage_compensation_pending_with_terminal_receipt(
                        operation_store.as_ref(),
                        &operation,
                        "durable executor readback proved the prepared dispatch never committed",
                    )?;
                }
                AdmissionOperationState::CompensationPending
                | AdmissionOperationState::CompensatedBeforeDispatch => break,
                AdmissionOperationState::DispatchCommitted
                | AdmissionOperationState::Completed
                | AdmissionOperationState::OutcomeUnknownAfterDispatch => {
                    return Err(never_committed_denied(
                        "governed admission operation is not eligible for pre-dispatch termination",
                    ));
                }
                _ => {
                    return Err(never_committed_internal(
                        "governed active response entered a tool-dispatch-only state",
                    ))
                }
            }
        }
        if !matches!(
            operation.state(),
            AdmissionOperationState::CompensationPending
                | AdmissionOperationState::CompensatedBeforeDispatch
        ) || operation.dispatch_state() != AdmissionDispatchState::NotStarted
        {
            return Err(never_committed_internal(
                "governed pre-dispatch termination did not converge",
            ));
        }
        if !self.recover_compensated_admission_operation(operation_id)? {
            return Err(never_committed_internal(
                "governed pre-dispatch cleanup is owned by another recovery worker",
            ));
        }

        let terminal = self.load_active_response_operation(operation_id)?;
        validate_durable_governed_operation_binding(
            self,
            response_plan,
            binding,
            &terminal,
            admission_operation_id,
            admission_operation_version,
            approval_set_hash,
        )?;
        if terminal.state() != AdmissionOperationState::CompensatedBeforeDispatch
            || terminal.dispatch_state() != AdmissionDispatchState::NotStarted
        {
            return Err(never_committed_internal(
                "governed admission operation did not remain terminally compensated",
            ));
        }
        let approval_after = approval_store
            .get_approval_reservation(operation_id)
            .map_err(|error| {
                never_committed_internal(format!(
                    "terminal approval reservation lookup failed: {error}"
                ))
            })?;
        if (approval_before.is_some()
            && !approval_after.as_ref().is_some_and(|reservation| {
                reservation.operation_id() == operation_id
                    && reservation.approval_set().approval_set_hash()
                        == approval_set_hash_hex.as_str()
                    && reservation.state() == ReplayReservationState::Cancelled
            }))
            || (approval_before.is_none() && approval_after.is_some())
        {
            return Err(never_committed_internal(
                "terminal approval cleanup does not match the prepared dispatch",
            ));
        }
        validate_approval_cleanup_actions(
            operation_store
                .load_cleanup_actions(operation_id)
                .map_err(|error| {
                    never_committed_internal(format!(
                        "terminal cleanup journal lookup failed: {error}"
                    ))
                })?,
            &terminal,
            true,
        )
    }

    fn validate_committed_governed_operation(
        &self,
        execution: &ActiveResponseExecutionRequest,
    ) -> Result<Option<ActiveResponseDispatchPermit>, KernelError> {
        let ActiveResponseExecutionApproval::Governed {
            admission_operation_id,
            admission_operation_version,
            approval_set_hash,
        } = execution.approval()
        else {
            return Ok(None);
        };
        let operation = self.load_active_response_operation(admission_operation_id)?;
        let expected_request_binding_hash = derive_active_response_operation_request_binding_hash(
            execution.plan_body_hash(),
            execution.executor_authority_id(),
            execution.executor_authority_generation(),
            execution.authorization_capability_hash(),
            execution.governed_intent_hash(),
            approval_set_hash,
            &digest_hex(&execution.response_plan().policy_hash),
        )?;
        if operation.kind() != AdmissionOperationKind::GovernedActiveResponse
            || !matches!(
                operation.state(),
                AdmissionOperationState::DispatchCommitted | AdmissionOperationState::Completed
            )
            || operation.dispatch_state()
                != if operation.state() == AdmissionOperationState::Completed {
                    AdmissionDispatchState::EffectCompleted
                } else {
                    AdmissionDispatchState::Committed
                }
            || operation.coordinator_authority_id() != execution.executor_authority_id()
            || operation.request_id() != execution.request_id()
            || operation.authorization_capability_hash()
                != execution.authorization_capability_hash()
            || operation.policy_hash() != digest_hex(&execution.response_plan().policy_hash)
            || operation.approval_set_hash() != Some(approval_set_hash.as_str())
            || operation.request_binding_hash() != expected_request_binding_hash
            || active_response_dispatch_operation_version(&operation)?
                != *admission_operation_version
        {
            return Err(committed_recovery_denied(
                "durable governed admission operation does not match the committed dispatch",
            ));
        }
        let expected_anchor = build_active_response_operation_anchor(
            execution.response_plan(),
            execution.executor_authority(),
            execution.authorized_at_unix_ms(),
            execution.authorization_capability_hash(),
            execution.governed_intent_hash(),
            execution.policy_decision_hash(),
            approval_set_hash,
        )?;
        if self.load_active_response_operation_anchor(&operation)? != expected_anchor {
            return Err(committed_recovery_denied(
                "durable governed admission anchor does not match the committed dispatch",
            ));
        }
        let approval = self
            .approval_store
            .as_ref()
            .ok_or_else(|| {
                committed_recovery_internal(
                    "durable active-response approval store is not installed",
                )
            })?
            .get_approval_reservation(admission_operation_id)
            .map_err(|error| {
                committed_recovery_internal(format!(
                    "committed active-response approval lookup failed: {error}"
                ))
            })?
            .ok_or_else(|| {
                committed_recovery_internal(
                    "committed active-response approval reservation is missing",
                )
            })?;
        if approval.operation_id() != admission_operation_id
            || approval.approval_set().approval_set_hash() != approval_set_hash
            || approval.state() != ReplayReservationState::Committed
        {
            return Err(committed_recovery_denied(
                "durable governed approval does not match the committed dispatch",
            ));
        }
        Ok(Some(ActiveResponseDispatchPermit {
            operation,
            recovery: true,
        }))
    }
}

fn validate_prepared_binding(
    response_plan: &ResponsePlan,
    binding: &PreparedActiveResponseDispatchBinding,
) -> Result<
    (
        ActiveResponseExecutorAuthorityIdentity,
        ActiveResponseExecutionApproval,
    ),
    KernelError,
> {
    binding
        .validate_for_plan(response_plan)
        .map_err(|error| never_committed_denied(error.to_string()))?;
    let subject = PublicKey::from_hex(response_plan.operator_capability.executor_subject.as_str())
        .map_err(|error| {
            never_committed_denied(format!("prepared executor subject is invalid: {error}"))
        })?;
    let executor = ActiveResponseExecutorAuthorityIdentity::new(
        subject,
        binding.executor_authority_generation,
    )
    .map_err(|error| never_committed_denied(error.to_string()))?;
    if executor.authority_id() != binding.executor_authority_id.as_str() {
        return Err(never_committed_denied(
            "prepared executor identity does not match the durable binding",
        ));
    }
    let approval = match &binding.approval {
        ResponseDispatchApproval::Automatic => ActiveResponseExecutionApproval::Automatic,
        ResponseDispatchApproval::Governed {
            admission_operation_id,
            admission_operation_version,
            approval_set_hash,
        } => ActiveResponseExecutionApproval::Governed {
            admission_operation_id: admission_operation_id.as_str().to_string(),
            admission_operation_version: *admission_operation_version,
            approval_set_hash: digest_hex(approval_set_hash),
        },
    };
    let expected_dispatch_id = derive_active_response_dispatch_id(
        response_plan,
        &executor,
        &digest_hex(&binding.authorization_capability_hash),
        &digest_hex(&binding.governed_intent_hash),
        &digest_hex(&binding.policy_decision_hash),
        binding.authorized_at_unix_ms,
        &approval,
    )
    .map_err(|error| active_response_denied(error.to_string()))?;
    if expected_dispatch_id != binding.dispatch_id {
        return Err(never_committed_denied(
            "prepared dispatch identifier is not canonical for its durable binding",
        ));
    }
    Ok((executor, approval))
}

fn execution_request_from_prepared_binding(
    response_plan: &ResponsePlan,
    binding: &PreparedActiveResponseDispatchBinding,
    executor_authority: ActiveResponseExecutorAuthorityIdentity,
    approval: ActiveResponseExecutionApproval,
    dispatch_committed_resume: bool,
) -> ActiveResponseExecutionRequest {
    ActiveResponseExecutionRequest::new(ActiveResponseExecutionRequestParts {
        response_plan: response_plan.clone(),
        dispatch_id: binding.dispatch_id.clone(),
        executor_authority,
        request_id: response_plan.action_id.as_str().to_string(),
        plan_body_hash: digest_hex(&response_plan.plan_hash),
        authorization_capability_hash: digest_hex(&binding.authorization_capability_hash),
        governed_intent_hash: digest_hex(&binding.governed_intent_hash),
        policy_decision_hash: digest_hex(&binding.policy_decision_hash),
        approval,
        authorized_at_unix_ms: binding.authorized_at_unix_ms,
        expires_at_unix_ms: response_plan.expires_at_unix_ms,
        dispatch_committed_resume,
    })
}

fn validate_durable_governed_operation_binding(
    kernel: &ChioKernel,
    response_plan: &ResponsePlan,
    binding: &PreparedActiveResponseDispatchBinding,
    operation: &AdmissionOperation,
    admission_operation_id: &RecordId,
    admission_operation_version: u64,
    approval_set_hash: &Digest32,
) -> Result<(), KernelError> {
    let authorization_capability_hash = digest_hex(&binding.authorization_capability_hash);
    let governed_intent_hash = digest_hex(&binding.governed_intent_hash);
    let policy_decision_hash = digest_hex(&binding.policy_decision_hash);
    let policy_hash = digest_hex(&response_plan.policy_hash);
    let approval_set_hash = digest_hex(approval_set_hash);
    let expected_request_binding_hash = derive_active_response_operation_request_binding_hash(
        &digest_hex(&binding.plan_hash),
        binding.executor_authority_id.as_str(),
        binding.executor_authority_generation,
        &authorization_capability_hash,
        &governed_intent_hash,
        &approval_set_hash,
        &policy_hash,
    )?;
    let stable_version_matches = match operation.state() {
        AdmissionOperationState::Prepared
        | AdmissionOperationState::ApprovalReserved
        | AdmissionOperationState::DispatchCommitted
        | AdmissionOperationState::Completed => {
            active_response_dispatch_operation_version(operation)? == admission_operation_version
        }
        AdmissionOperationState::CompensationPending
        | AdmissionOperationState::CompensatedBeforeDispatch => {
            operation.version() == admission_operation_version
                || operation.version().checked_add(1) == Some(admission_operation_version)
                || admission_operation_version.checked_add(1) == Some(operation.version())
                || admission_operation_version.checked_add(2) == Some(operation.version())
        }
        _ => false,
    };
    if operation.operation_id() != admission_operation_id.as_str()
        || operation.kind() != AdmissionOperationKind::GovernedActiveResponse
        || operation.coordinator_authority_id() != binding.executor_authority_id.as_str()
        || operation.request_id() != response_plan.action_id.as_str()
        || operation.authorization_capability_hash() != authorization_capability_hash.as_str()
        || operation.policy_hash() != policy_hash.as_str()
        || operation.approval_set_hash() != Some(approval_set_hash.as_str())
        || operation.request_binding_hash() != expected_request_binding_hash
        || !stable_version_matches
    {
        return Err(never_committed_denied(
            "durable governed operation does not match the prepared dispatch",
        ));
    }
    let (executor_authority, _) = validate_prepared_binding(response_plan, binding)?;
    let expected_anchor = build_active_response_operation_anchor(
        response_plan,
        &executor_authority,
        binding.authorized_at_unix_ms,
        &authorization_capability_hash,
        &governed_intent_hash,
        &policy_decision_hash,
        &approval_set_hash,
    )?;
    if kernel.load_active_response_operation_anchor(operation)? != expected_anchor {
        return Err(never_committed_denied(
            "durable governed operation anchor does not match the prepared dispatch",
        ));
    }
    Ok(())
}

fn validate_approval_cleanup_actions(
    actions: Vec<AdmissionCleanupAction>,
    operation: &AdmissionOperation,
    require_completed: bool,
) -> Result<(), KernelError> {
    let mut approval_actions = actions
        .iter()
        .filter(|action| action.kind() == AdmissionCleanupActionKind::Approval);
    let Some(action) = approval_actions.next() else {
        return Err(never_committed_internal(
            "prepared governed response lacks one exact approval cleanup action",
        ));
    };
    if approval_actions.next().is_some() {
        return Err(never_committed_internal(
            "prepared governed response has multiple approval cleanup actions",
        ));
    }
    if action.operation_id() != operation.operation_id()
        || action.request_binding_hash() != operation.request_binding_hash()
        || action.kind() != AdmissionCleanupActionKind::Approval
        || require_completed && action.state() != AdmissionCleanupActionState::Completed
        || !require_completed
            && !matches!(
                operation.state(),
                AdmissionOperationState::CompensationPending
                    | AdmissionOperationState::CompensatedBeforeDispatch
            )
            && action.state() == AdmissionCleanupActionState::Completed
    {
        return Err(never_committed_internal(
            "prepared approval cleanup journal does not match the governed operation",
        ));
    }
    let terminal_actions = actions
        .iter()
        .filter(|action| action.kind() == AdmissionCleanupActionKind::TerminalReceipt)
        .collect::<Vec<_>>();
    if require_completed {
        if terminal_actions.len() != 1
            || terminal_actions[0].state() != AdmissionCleanupActionState::Completed
        {
            return Err(never_committed_internal(
                "terminal governed response lacks one completed signed receipt outbox",
            ));
        }
    } else if terminal_actions.len() > 1 {
        return Err(never_committed_internal(
            "prepared governed response has multiple terminal receipt outboxes",
        ));
    }
    Ok(())
}

fn validate_committed_dispatch(
    expected_plan: &ResponsePlan,
    expected_dispatch_id: &RecordId,
    executor: &super::ActiveResponseExecutorAuthorityIdentity,
    committed: &ActiveResponseCommittedDispatch,
) -> Result<ActiveResponseExecutionRequest, KernelError> {
    if committed.response_plan() != expected_plan {
        return Err(committed_recovery_denied(
            "durable dispatch response plan does not match the requested recovery plan",
        ));
    }
    let authorization = committed.authorization();
    let canonical_authorization = canonical_json_bytes(&authorization.body).map_err(|error| {
        committed_recovery_internal(format!(
            "committed dispatch authorization canonicalization failed: {error}"
        ))
    })?;
    let authorization_hash = Digest32::new(*sha256(&canonical_authorization).as_bytes());
    let body = &authorization.body;
    if canonical_authorization.as_slice() != authorization.canonical_body.as_bytes()
        || authorization_hash != authorization.body_hash
        || authorization.body_hash.is_zero()
        || body.schema_version != RESPONSE_DISPATCH_AUTHORIZATION_SCHEMA_VERSION
        || body.key.tenant_id != expected_plan.tenant_id
        || &body.key.dispatch_id != expected_dispatch_id
        || body.action_id != expected_plan.action_id
        || body.plan_hash != expected_plan.plan_hash
        || body.response_body_hash.is_zero()
        || body.authorization_capability_hash != expected_plan.operator_capability.capability_digest
        || body.governed_intent_hash.is_zero()
        || body.policy_decision_hash.is_zero()
        || body.executor_authority_id.as_str() != executor.authority_id()
        || body.executor_authority_generation != executor.generation()
        || body.authorized_at_unix_ms < expected_plan.created_at_unix_ms
        || body.authorized_at_unix_ms >= expected_plan.expires_at_unix_ms
        || expected_plan.operator_capability.executor_subject.as_str()
            != executor.subject().to_hex()
    {
        return Err(committed_recovery_denied(
            "committed dispatch authorization does not match the exact recovery binding",
        ));
    }

    let response_record = committed.committed_response_record();
    let snapshot: ResponseSnapshot =
        serde_json::from_slice(response_record.canonical_body.as_bytes())
            .map_err(|_| committed_recovery_denied("committed response record is not decodable"))?;
    let canonical_response = canonical_json_bytes(&snapshot).map_err(|error| {
        committed_recovery_internal(format!(
            "committed response canonicalization failed: {error}"
        ))
    })?;
    let response_hash = Digest32::new(*sha256(&canonical_response).as_bytes());
    let mut normalized_snapshot = snapshot.clone();
    normalized_snapshot.dispatch_authorization_hash = None;
    let normalized_response = canonical_json_bytes(&normalized_snapshot).map_err(|error| {
        committed_recovery_internal(format!(
            "normalized committed response canonicalization failed: {error}"
        ))
    })?;
    let normalized_response_hash = Digest32::new(*sha256(&normalized_response).as_bytes());
    let expected_binding = ResponseExecutionDispatchBinding {
        schema_version: body.schema_version,
        tenant_id: body.key.tenant_id.clone(),
        dispatch_id: body.key.dispatch_id.clone(),
        action_id: body.action_id.clone(),
        plan_hash: body.plan_hash,
        executor_authority_id: body.executor_authority_id.clone(),
        executor_authority_generation: body.executor_authority_generation,
        authorization_capability_hash: body.authorization_capability_hash,
        governed_intent_hash: body.governed_intent_hash,
        policy_decision_hash: body.policy_decision_hash,
        approval: body.approval.clone(),
        authorized_at_unix_ms: body.authorized_at_unix_ms,
    };
    expected_binding
        .validate_for_plan(expected_plan)
        .map_err(|error| committed_recovery_denied(error.to_string()))?;
    if canonical_response.as_slice() != response_record.canonical_body.as_bytes()
        || response_hash != response_record.body_hash
        || response_record.tenant_id != expected_plan.tenant_id
        || response_record.action_id != expected_plan.action_id
        || response_record.generation != snapshot.generation
        || response_record.state.as_str() != snapshot.state.as_str()
        || response_record.due_at_unix_ms != snapshot.due_at_unix_ms
        || snapshot.plan != *expected_plan
        || snapshot.state != ResponseState::Applying
        || snapshot.execution_dispatch.as_ref() != Some(&expected_binding)
        || snapshot.dispatch_authorization_hash != Some(authorization.body_hash)
        || normalized_response_hash != authorization.body.response_body_hash
        || !committed_response_history_is_exact(&snapshot, body.authorized_at_unix_ms)
    {
        return Err(committed_recovery_denied(
            "committed response record does not match its dispatch authorization",
        ));
    }

    let approval = match &body.approval {
        ResponseDispatchApproval::Automatic
            if matches!(
                &expected_plan.approval_requirement,
                chio_security_types::ResponseApprovalRequirement::Automatic
            ) =>
        {
            ActiveResponseExecutionApproval::Automatic
        }
        ResponseDispatchApproval::Governed {
            admission_operation_id,
            admission_operation_version,
            approval_set_hash,
        } if matches!(
            &expected_plan.approval_requirement,
            chio_security_types::ResponseApprovalRequirement::Governed { .. }
        ) =>
        {
            ActiveResponseExecutionApproval::Governed {
                admission_operation_id: admission_operation_id.as_str().to_string(),
                admission_operation_version: *admission_operation_version,
                approval_set_hash: digest_hex(approval_set_hash),
            }
        }
        _ => {
            return Err(committed_recovery_denied(
                "committed dispatch approval mode does not match the recovery plan",
            ))
        }
    };
    let authorization_capability_hash = digest_hex(&body.authorization_capability_hash);
    let governed_intent_hash = digest_hex(&body.governed_intent_hash);
    let policy_decision_hash = digest_hex(&body.policy_decision_hash);
    let derived_dispatch_id = derive_active_response_dispatch_id(
        expected_plan,
        executor,
        &authorization_capability_hash,
        &governed_intent_hash,
        &policy_decision_hash,
        body.authorized_at_unix_ms,
        &approval,
    )
    .map_err(|error| active_response_denied(error.to_string()))?;
    if &derived_dispatch_id != expected_dispatch_id {
        return Err(committed_recovery_denied(
            "committed dispatch identifier is not the canonical recovery identifier",
        ));
    }
    Ok(ActiveResponseExecutionRequest::new(
        ActiveResponseExecutionRequestParts {
            response_plan: expected_plan.clone(),
            dispatch_id: expected_dispatch_id.clone(),
            executor_authority: executor.clone(),
            request_id: expected_plan.action_id.as_str().to_string(),
            plan_body_hash: digest_hex(&expected_plan.plan_hash),
            authorization_capability_hash,
            governed_intent_hash,
            policy_decision_hash,
            approval,
            authorized_at_unix_ms: body.authorized_at_unix_ms,
            expires_at_unix_ms: expected_plan.expires_at_unix_ms,
            dispatch_committed_resume: false,
        },
    ))
}

fn committed_response_history_is_exact(
    snapshot: &ResponseSnapshot,
    authorized_at_unix_ms: u64,
) -> bool {
    if snapshot.schema_version != RESPONSE_STATE_SCHEMA_VERSION
        || snapshot.operator_page_required
        || snapshot.due_at_unix_ms != snapshot.applying_lease_expires_at_unix_ms
        || snapshot
            .applying_lease_expires_at_unix_ms
            .is_none_or(|lease| {
                lease <= authorized_at_unix_ms || lease > snapshot.plan.expires_at_unix_ms
            })
    {
        return false;
    }
    let mutations = snapshot.mutations.as_slice();
    let Some(ResponseMutationRecord::Requested(requested)) = mutations.first() else {
        return false;
    };
    if requested.generation != 0
        || requested.occurred_at_unix_ms != snapshot.plan.created_at_unix_ms
        || requested.prior_receipt_id != snapshot.plan.trigger_finding_receipt_id
        || record_id_is_zero_sentinel(&requested.transition_id)
    {
        return false;
    }
    let applying_transition_is_exact =
        |mutation: &ResponseMutationRecord,
         generation: u64,
         from_state: ResponseState,
         cause: ResponseTransitionCause| {
            matches!(
                mutation,
                ResponseMutationRecord::Transition(transition)
                    if transition.generation == generation
                        && transition.from_state == from_state
                        && transition.to_state == ResponseState::Applying
                        && transition.cause == cause
                        && transition.occurred_at_unix_ms == authorized_at_unix_ms
                        && transition.applying_lease_expires_at_unix_ms
                            == snapshot.applying_lease_expires_at_unix_ms
                        && transition.scheduler_lease_owner_id.is_none()
                        && transition.scheduler_fencing_token.is_none()
                        && !record_id_is_zero_sentinel(&transition.transition_id)
            )
        };
    match (&snapshot.plan.approval_requirement, mutations) {
        (
            chio_security_types::ResponseApprovalRequirement::Automatic,
            [ResponseMutationRecord::Requested(_), applying],
        ) => {
            snapshot.generation == 1
                && applying_transition_is_exact(
                    applying,
                    1,
                    ResponseState::Planned,
                    ResponseTransitionCause::ApplyStarted,
                )
        }
        (
            chio_security_types::ResponseApprovalRequirement::Governed { .. },
            [ResponseMutationRecord::Requested(_), approval, applying],
        ) => {
            snapshot.generation == 2
                && matches!(
                    approval,
                    ResponseMutationRecord::Transition(transition)
                        if transition.generation == 1
                            && transition.from_state == ResponseState::Planned
                            && transition.to_state == ResponseState::AwaitingApproval
                            && transition.cause == ResponseTransitionCause::ApprovalRequested
                            && transition.occurred_at_unix_ms
                                == snapshot.plan.created_at_unix_ms
                            && transition.applying_lease_expires_at_unix_ms.is_none()
                            && transition.scheduler_lease_owner_id.is_none()
                            && transition.scheduler_fencing_token.is_none()
                            && !record_id_is_zero_sentinel(&transition.transition_id)
                )
                && applying_transition_is_exact(
                    applying,
                    2,
                    ResponseState::AwaitingApproval,
                    ResponseTransitionCause::ApprovalSatisfied,
                )
        }
        _ => false,
    }
}

fn record_id_is_zero_sentinel(value: &RecordId) -> bool {
    !value.as_str().is_empty() && value.as_str().bytes().all(|byte| byte == b'0')
}

fn digest_hex(digest: &Digest32) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in digest.as_bytes() {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn digest_from_hex(value: &str, label: &str) -> Result<Digest32, KernelError> {
    let digest = Hash::from_hex(value)
        .map_err(|_| never_committed_internal(format!("prepared {label} hash is invalid")))?;
    if digest.to_hex() != value || digest.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(never_committed_internal(format!(
            "prepared {label} hash is zero or not canonical lowercase hexadecimal"
        )));
    }
    Ok(Digest32::new(*digest.as_bytes()))
}

fn map_executor_lookup_error(error: ActiveResponseExecutorError) -> KernelError {
    match error {
        ActiveResponseExecutorError::RejectedBeforeCommit(reason) => committed_recovery_denied(
            format!("committed active-response dispatch readback was rejected: {reason}"),
        ),
        ActiveResponseExecutorError::NotReady(reason)
        | ActiveResponseExecutorError::OutcomeUnknown(reason) => committed_recovery_internal(
            format!("committed active-response dispatch readback failed: {reason}"),
        ),
    }
}

fn map_automatic_dispatch_fence_error(error: ActiveResponseExecutorError) -> KernelError {
    match error {
        ActiveResponseExecutorError::RejectedBeforeCommit(reason) => never_committed_denied(
            format!("automatic active-response dispatch fence was rejected: {reason}"),
        ),
        ActiveResponseExecutorError::NotReady(reason)
        | ActiveResponseExecutorError::OutcomeUnknown(reason) => never_committed_internal(format!(
            "automatic active-response dispatch fence failed: {reason}"
        )),
    }
}

fn committed_recovery_denied(reason: impl Into<String>) -> KernelError {
    KernelError::GovernedTransactionDenied(format!(
        "active-response committed recovery denied: {}",
        reason.into()
    ))
}

fn committed_recovery_internal(reason: impl Into<String>) -> KernelError {
    KernelError::Internal(format!(
        "active-response committed recovery failed: {}",
        reason.into()
    ))
}

fn committed_resume_denied(reason: impl Into<String>) -> KernelError {
    KernelError::GovernedTransactionDenied(format!(
        "active-response dispatch-committed resume denied: {}",
        reason.into()
    ))
}

fn committed_resume_internal(reason: impl Into<String>) -> KernelError {
    KernelError::Internal(format!(
        "active-response dispatch-committed resume failed: {}",
        reason.into()
    ))
}

fn never_committed_denied(reason: impl Into<String>) -> KernelError {
    KernelError::GovernedTransactionDenied(format!(
        "active-response never-committed termination denied: {}",
        reason.into()
    ))
}

fn never_committed_internal(reason: impl Into<String>) -> KernelError {
    KernelError::Internal(format!(
        "active-response never-committed termination failed: {}",
        reason.into()
    ))
}
