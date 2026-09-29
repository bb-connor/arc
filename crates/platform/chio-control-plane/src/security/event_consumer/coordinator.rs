

use super::ActiveResponseAdmissionRequest;
use super::ActiveResponseExecutionEvidence;
use super::ActiveResponseExecutionOutcome;
use super::ActiveResponseExecutorAuthorityIdentity;

use super::ChioKernel;
use super::DispatchCommittedActiveResponseResume;
use super::KernelError;
use super::PreDispatchActiveResponseReconstruction;
use super::PreparedActiveResponseAdmission;
use super::ApprovalCoordinatorError;
use super::ResponseApprovalCoordinator;
use super::Clock;
use super::ApprovalVerifierPort;
use super::AttestedFindingResponseCompletionOutcome;
use super::Digest32;
use super::ErrorCode;
use super::GovernedApprovalRequest;
use super::GovernedApprovalReservation;
use super::GovernedApprovalReservationMutation;
use super::OpaqueReceiptRef;
use super::PortError;
use super::PortErrorKind;
use super::PortResult;
use super::PreparedActiveResponseDispatchBinding;
use super::RecordId;
# [cfg (test)]
use super::ResponseDispatchApproval;
# [cfg (test)]
use super::PREPARED_ACTIVE_RESPONSE_DISPATCH_BINDING_SCHEMA_VERSION;
use super::ResponseApprovalRequirement;
use super::ResponsePlan;
use super::Arc;
use super::Mutex;




use super::AttestedFindingAdmissionArtifacts;
use super::governed_approval_request_from_native;


use super::ReservedAttestedFindingResponsePlan;


pub(crate) enum PreparedAttestedFindingResponse {
    Kernel(Box<KernelPreparedAttestedFindingResponse>),
    #[cfg(test)]
    Synthetic {
        dispatch_id: RecordId,
    },
}

pub(crate) struct KernelPreparedAttestedFindingResponse {
    request: ActiveResponseAdmissionRequest,
    prepared: PreparedActiveResponseAdmission,
    governed_approval: Option<GovernedApprovalReservation>,
}

impl PreparedAttestedFindingResponse {
    fn kernel_prepared(&self) -> PortResult<&KernelPreparedAttestedFindingResponse> {
        match self {
            Self::Kernel(response) => Ok(response.as_ref()),
            #[cfg(test)]
            Self::Synthetic { .. } => Err(PortError::integrity_failure()),
        }
    }

    #[must_use]
    pub(crate) fn dispatch_id(&self) -> &RecordId {
        match self {
            Self::Kernel(response) => response.prepared.dispatch_id(),
            #[cfg(test)]
            Self::Synthetic { dispatch_id } => dispatch_id,
        }
    }

    pub(super) fn durable_dispatch_binding(
        &self,
        response_plan: &ResponsePlan,
    ) -> PortResult<PreparedActiveResponseDispatchBinding> {
        let binding = match self {
            Self::Kernel(response) => response
                .prepared
                .durable_dispatch_binding(response_plan)
                .map_err(map_active_response_kernel_error)?,
            #[cfg(test)]
            Self::Synthetic { dispatch_id } => {
                synthetic_prepared_dispatch_binding(response_plan, dispatch_id.clone())?
            }
        };
        binding
            .validate_for_plan(response_plan)
            .map_err(|_| PortError::integrity_failure())?;
        if binding.dispatch_id != *self.dispatch_id() {
            return Err(PortError::integrity_failure());
        }
        match self {
            Self::Kernel(response) => match (
                &response_plan.approval_requirement,
                &response.governed_approval,
            ) {
                (ResponseApprovalRequirement::Automatic, None) => {}
                (ResponseApprovalRequirement::Governed { .. }, Some(reservation))
                    if reservation.prepared_dispatch_binding == binding => {}
                _ => return Err(PortError::integrity_failure()),
            },
            #[cfg(test)]
            Self::Synthetic { .. } => {}
        }
        Ok(binding)
    }

    #[cfg(test)]
    pub(super) fn synthetic(dispatch_id: RecordId) -> Self {
        Self::Synthetic { dispatch_id }
    }
}

#[cfg(test)]
pub(super) fn synthetic_prepared_dispatch_binding(
    response_plan: &ResponsePlan,
    dispatch_id: RecordId,
) -> PortResult<PreparedActiveResponseDispatchBinding> {
    let approval = match &response_plan.approval_requirement {
        ResponseApprovalRequirement::Automatic => ResponseDispatchApproval::Automatic,
        ResponseApprovalRequirement::Governed { .. } => ResponseDispatchApproval::Governed {
            admission_operation_id: RecordId::new(format!(
                "synthetic-admission-operation-{}",
                response_plan.action_id.as_str()
            ))
            .map_err(|_| PortError::integrity_failure())?,
            admission_operation_version: 1,
            approval_set_hash: Digest32::new([93_u8; 32]),
        },
    };
    let binding = PreparedActiveResponseDispatchBinding {
        schema_version: PREPARED_ACTIVE_RESPONSE_DISPATCH_BINDING_SCHEMA_VERSION,
        tenant_id: response_plan.tenant_id.clone(),
        action_id: response_plan.action_id.clone(),
        plan_hash: response_plan.plan_hash,
        dispatch_id,
        executor_authority_id: RecordId::new("synthetic-executor-authority")
            .map_err(|_| PortError::integrity_failure())?,
        executor_authority_generation: 1,
        authorized_at_unix_ms: response_plan.created_at_unix_ms,
        authorization_capability_hash: response_plan.operator_capability.capability_digest,
        governed_intent_hash: Digest32::new([94_u8; 32]),
        policy_decision_hash: Digest32::new([95_u8; 32]),
        approval,
    };
    binding
        .validate_for_plan(response_plan)
        .map_err(|_| PortError::integrity_failure())?;
    Ok(binding)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AttestedFindingResponseCompletionProof {
    dispatch_id: RecordId,
    outcome: AttestedFindingResponseCompletionOutcome,
    evidence_id: OpaqueReceiptRef,
    evidence_body_hash: Digest32,
}

impl AttestedFindingResponseCompletionProof {
    #[must_use]
    pub(super) fn dispatch_id(&self) -> &RecordId {
        &self.dispatch_id
    }

    #[must_use]
    pub(super) const fn outcome(&self) -> AttestedFindingResponseCompletionOutcome {
        self.outcome
    }

    #[must_use]
    pub(super) fn evidence_id(&self) -> &OpaqueReceiptRef {
        &self.evidence_id
    }

    #[must_use]
    pub(super) const fn evidence_body_hash(&self) -> &Digest32 {
        &self.evidence_body_hash
    }

    #[cfg(test)]
    pub(super) fn synthetic(
        dispatch_id: RecordId,
        outcome: AttestedFindingResponseCompletionOutcome,
        evidence_id: OpaqueReceiptRef,
        evidence_body_hash: Digest32,
    ) -> Self {
        Self {
            dispatch_id,
            outcome,
            evidence_id,
            evidence_body_hash,
        }
    }
}

pub(crate) enum AttestedFindingDispatchCommittedResume {
    NotDispatchCommitted,
    Completed(AttestedFindingResponseCompletionProof),
}

pub(crate) enum AttestedFindingPreDispatchReconstruction {
    NotPrepared,
    Prepared(Box<PreparedAttestedFindingResponse>),
}

pub(crate) trait AttestedFindingResponseCoordinator: Send + Sync {
    fn execution_mode(&self) -> chio_security_types::ResponseExecutionMode {
        chio_security_types::ResponseExecutionMode::Live
    }
    fn recover_simulation(
        &self,
        _plan: &ResponsePlan,
    ) -> PortResult<Option<chio_kernel::response_simulation_report::ResponseSimulationReport>> {
        Err(PortError::invalid_data())
    }
    fn simulate(
        &self,
        _plan: &ReservedAttestedFindingResponsePlan,
        _artifacts: AttestedFindingAdmissionArtifacts,
    ) -> PortResult<chio_kernel::response_simulation_report::ResponseSimulationReport> {
        Err(PortError::invalid_data())
    }

    fn ensure_configured(&self) -> PortResult<()> {
        self.ensure_ready()
    }

    fn ensure_ready(&self) -> PortResult<()>;

    /// Recover only an exact durable dispatch already committed by the
    /// executor. `None` is a point-in-time Missing result. An expired prepared
    /// row may enter exact never-committed termination; an unexpired row must
    /// first reconstruct the current live admission request.
    fn recover_committed(
        &self,
        response_plan: &ResponsePlan,
        dispatch_id: &RecordId,
    ) -> PortResult<Option<AttestedFindingResponseCompletionProof>>;

    fn resume_dispatch_committed(
        &self,
        response_plan: &ResponsePlan,
        binding: &PreparedActiveResponseDispatchBinding,
    ) -> PortResult<AttestedFindingDispatchCommittedResume>;

    fn reconstruct_pre_dispatch(
        &self,
        plan: &ReservedAttestedFindingResponsePlan,
        artifacts: AttestedFindingAdmissionArtifacts,
        binding: &PreparedActiveResponseDispatchBinding,
    ) -> PortResult<AttestedFindingPreDispatchReconstruction>;

    fn terminate_never_committed(
        &self,
        response_plan: &ResponsePlan,
        binding: &PreparedActiveResponseDispatchBinding,
        current_artifacts: Option<&AttestedFindingAdmissionArtifacts>,
    ) -> PortResult<()>;

    fn prepare_admission(
        &self,
        plan: &ReservedAttestedFindingResponsePlan,
        artifacts: AttestedFindingAdmissionArtifacts,
    ) -> PortResult<PreparedAttestedFindingResponse>;

    fn cancel_prepared(
        &self,
        plan: &ReservedAttestedFindingResponsePlan,
        prepared: &PreparedAttestedFindingResponse,
    ) -> PortResult<()>;

    fn execute_prepared(
        &self,
        plan: &ReservedAttestedFindingResponsePlan,
        prepared: PreparedAttestedFindingResponse,
    ) -> PortResult<AttestedFindingResponseCompletionProof>;
}

/// One-call adapter from the portable quarantine approval boundary to the
/// kernel's sole governed admission authority.
///
/// The adapter is scoped to one exact portable request and one exact native
/// request. It never keeps a process-global approval map. Crash recovery
/// recreates it from authenticated artifacts plus the durable dispatch
/// binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum KernelActiveResponseApprovalVerifierScope {
    Prepare,
    Reconstruct,
    Commit,
    Cancel,
}

pub(super) struct KernelActiveResponseApprovalVerifier<'a> {
    kernel: &'a ChioKernel,
    expected_request: &'a GovernedApprovalRequest,
    native_request: &'a ActiveResponseAdmissionRequest,
    prepared: Mutex<Option<PreparedActiveResponseAdmission>>,
    scope: KernelActiveResponseApprovalVerifierScope,
}

impl<'a> KernelActiveResponseApprovalVerifier<'a> {
    pub(super) fn for_prepare(
        kernel: &'a ChioKernel,
        expected_request: &'a GovernedApprovalRequest,
        native_request: &'a ActiveResponseAdmissionRequest,
    ) -> Self {
        Self {
            kernel,
            expected_request,
            native_request,
            prepared: Mutex::new(None),
            scope: KernelActiveResponseApprovalVerifierScope::Prepare,
        }
    }

    pub(super) fn for_reconstruction(
        kernel: &'a ChioKernel,
        expected_request: &'a GovernedApprovalRequest,
        native_request: &'a ActiveResponseAdmissionRequest,
    ) -> Self {
        Self {
            kernel,
            expected_request,
            native_request,
            prepared: Mutex::new(None),
            scope: KernelActiveResponseApprovalVerifierScope::Reconstruct,
        }
    }

    pub(super) fn for_commit(
        kernel: &'a ChioKernel,
        expected_request: &'a GovernedApprovalRequest,
        native_request: &'a ActiveResponseAdmissionRequest,
        prepared: PreparedActiveResponseAdmission,
    ) -> Self {
        Self {
            kernel,
            expected_request,
            native_request,
            prepared: Mutex::new(Some(prepared)),
            scope: KernelActiveResponseApprovalVerifierScope::Commit,
        }
    }

    pub(super) fn for_cancel(
        kernel: &'a ChioKernel,
        expected_request: &'a GovernedApprovalRequest,
        native_request: &'a ActiveResponseAdmissionRequest,
        prepared: PreparedActiveResponseAdmission,
    ) -> Self {
        Self {
            kernel,
            expected_request,
            native_request,
            prepared: Mutex::new(Some(prepared)),
            scope: KernelActiveResponseApprovalVerifierScope::Cancel,
        }
    }

    fn require_exact_request(&self, request: &GovernedApprovalRequest) -> PortResult<()> {
        let native_projection = governed_approval_request_from_native(self.native_request)?;
        if request != self.expected_request || request != &native_projection {
            return Err(PortError::integrity_failure());
        }
        Ok(())
    }

    fn retain_prepared(&self, prepared: PreparedActiveResponseAdmission) -> PortResult<()> {
        let mut retained = self.prepared.lock().map_err(|_| PortError::unavailable())?;
        if retained
            .as_ref()
            .is_some_and(|existing| existing != &prepared)
        {
            return Err(PortError::integrity_failure());
        }
        *retained = Some(prepared);
        Ok(())
    }

    fn retained_prepared(&self) -> PortResult<PreparedActiveResponseAdmission> {
        self.prepared
            .lock()
            .map_err(|_| PortError::unavailable())?
            .clone()
            .ok_or_else(PortError::integrity_failure)
    }

    fn reservation_for(
        &self,
        prepared: &PreparedActiveResponseAdmission,
    ) -> PortResult<GovernedApprovalReservation> {
        if !matches!(prepared, PreparedActiveResponseAdmission::Governed(_)) {
            return Err(PortError::integrity_failure());
        }
        let prepared_dispatch_binding = prepared
            .durable_dispatch_binding(self.native_request.response_plan())
            .map_err(map_active_response_kernel_error)?;
        Ok(GovernedApprovalReservation {
            request: self.expected_request.clone(),
            prepared_dispatch_binding,
            expires_at_unix_ms: self.expected_request.proposal_expires_at_unix_ms,
        })
    }
}

impl ApprovalVerifierPort for KernelActiveResponseApprovalVerifier<'_> {
    fn verify_and_reserve(
        &self,
        request: &GovernedApprovalRequest,
    ) -> PortResult<GovernedApprovalReservation> {
        if self.scope != KernelActiveResponseApprovalVerifierScope::Prepare {
            return Err(PortError::integrity_failure());
        }
        self.require_exact_request(request)?;
        let prepared = self
            .kernel
            .prepare_active_response_admission(self.native_request)
            .map_err(map_active_response_kernel_error)?;
        let reservation = self.reservation_for(&prepared)?;
        self.retain_prepared(prepared)?;
        Ok(reservation)
    }

    fn reconstruct(
        &self,
        request: &GovernedApprovalRequest,
        retained: &GovernedApprovalReservation,
    ) -> PortResult<Option<GovernedApprovalReservation>> {
        if self.scope != KernelActiveResponseApprovalVerifierScope::Reconstruct {
            return Err(PortError::integrity_failure());
        }
        self.require_exact_request(request)?;
        if &retained.request != request {
            return Err(PortError::integrity_failure());
        }
        let prepared = match self
            .kernel
            .reconstruct_pre_dispatch_active_response_admission(
                self.native_request,
                &retained.prepared_dispatch_binding,
            )
            .map_err(map_active_response_kernel_error)?
        {
            PreDispatchActiveResponseReconstruction::NotPrepared => return Ok(None),
            PreDispatchActiveResponseReconstruction::Prepared(prepared) => prepared,
        };
        let reconstructed = self.reservation_for(&prepared)?;
        if &reconstructed != retained {
            return Err(PortError::integrity_failure());
        }
        self.retain_prepared(prepared)?;
        Ok(Some(reconstructed))
    }

    fn commit(&self, mutation: &GovernedApprovalReservationMutation) -> PortResult<()> {
        if self.scope != KernelActiveResponseApprovalVerifierScope::Commit {
            return Err(PortError::integrity_failure());
        }
        self.require_exact_request(&mutation.reservation.request)?;
        let prepared = self.retained_prepared()?;
        if self.reservation_for(&prepared)? != mutation.reservation {
            return Err(PortError::integrity_failure());
        }
        self.kernel
            .commit_prepared_active_response_admission(self.native_request, &prepared)
            .map_err(map_active_response_kernel_error)
    }

    fn cancel(&self, mutation: &GovernedApprovalReservationMutation) -> PortResult<()> {
        if self.scope != KernelActiveResponseApprovalVerifierScope::Cancel {
            return Err(PortError::integrity_failure());
        }
        self.require_exact_request(&mutation.reservation.request)?;
        let prepared = self.retained_prepared()?;
        if self.reservation_for(&prepared)? != mutation.reservation {
            return Err(PortError::integrity_failure());
        }
        self.kernel
            .cancel_prepared_active_response_admission(
                &prepared,
                "durable response preparation was not published",
            )
            .map_err(map_active_response_kernel_error)
    }
}

/// Production-only bridge from correlation planning to the verified kernel
/// active-response admission and execution coordinator.
pub struct KernelAttestedFindingResponseCoordinator {
    kernel: Mutex<Option<Arc<ChioKernel>>>,
    executor_authority: ActiveResponseExecutorAuthorityIdentity,
    clock: Arc<dyn Clock>,
    profile: super::super::response_simulation::ActiveResponseExecutionProfile,
}

impl KernelAttestedFindingResponseCoordinator {
    #[must_use]
    pub fn new_unbound(
        executor_authority: ActiveResponseExecutorAuthorityIdentity,
        clock: Arc<dyn Clock>,
        profile: super::super::response_simulation::ActiveResponseExecutionProfile,
    ) -> Self {
        Self {
            kernel: Mutex::new(None),
            executor_authority,
            clock,
            profile,
        }
    }

    pub fn bind_kernel(&self, kernel: Arc<ChioKernel>) -> PortResult<()> {
        self.validate_kernel(kernel.as_ref())?;
        let mut installed = self.kernel.lock().map_err(|_| PortError::unavailable())?;
        match installed.as_ref() {
            Some(retained) if Arc::ptr_eq(retained, &kernel) => Ok(()),
            Some(_) => Err(PortError::conflict()),
            None => {
                *installed = Some(kernel);
                Ok(())
            }
        }
    }

    fn bound_kernel(&self) -> PortResult<Arc<ChioKernel>> {
        self.kernel
            .lock()
            .map_err(|_| PortError::unavailable())?
            .as_ref()
            .cloned()
            .ok_or_else(PortError::unavailable)
    }

    fn validate_kernel(&self, kernel: &ChioKernel) -> PortResult<()> {
        let status = kernel.governed_security_runtime_status();
        if status.publication_generation == 0
            || !status.active_response_enabled
            || !status.threshold_approval_enabled
            || !status.capability_issuance_admission_enabled
            || status.executor_authority.as_ref() != Some(&self.executor_authority)
            || status.admission_operation_store_profile.is_none()
            || status.approval_store_profile.is_none()
        {
            return Err(PortError::unavailable());
        }
        Ok(())
    }
}

impl AttestedFindingResponseCoordinator for KernelAttestedFindingResponseCoordinator {
    fn execution_mode(&self) -> chio_security_types::ResponseExecutionMode {
        match self.profile {
            super::super::response_simulation::ActiveResponseExecutionProfile::Live => {
                chio_security_types::ResponseExecutionMode::Live
            }
            super::super::response_simulation::ActiveResponseExecutionProfile::DryRun(_) => {
                chio_security_types::ResponseExecutionMode::DryRun
            }
        }
    }

    fn recover_simulation(
        &self,
        plan: &ResponsePlan,
    ) -> PortResult<Option<chio_kernel::response_simulation_report::ResponseSimulationReport>> {
        let super::super::response_simulation::ActiveResponseExecutionProfile::DryRun(service) =
            &self.profile
        else {
            return Err(PortError::invalid_data());
        };
        service
            .load(plan)
            .map(|result| result.map(|(report, _)| report))
    }

    fn simulate(
        &self,
        plan: &ReservedAttestedFindingResponsePlan,
        artifacts: AttestedFindingAdmissionArtifacts,
    ) -> PortResult<chio_kernel::response_simulation_report::ResponseSimulationReport> {
        let super::super::response_simulation::ActiveResponseExecutionProfile::DryRun(service) =
            &self.profile
        else {
            return Err(PortError::invalid_data());
        };
        let kernel = self.bound_kernel()?;
        self.validate_kernel(kernel.as_ref())?;
        if plan.admission_artifact_digest()
            != Some(&artifacts.canonical_digest(plan.response_plan())?)
        {
            return Err(PortError::integrity_failure());
        }
        let request = artifacts
            .into_simulation_request(plan.response_plan().clone())
            .map_err(map_active_response_kernel_error)?;
        service
            .run(kernel.as_ref(), &request)
            .map(|(report, _)| report)
    }

    fn ensure_configured(&self) -> PortResult<()> {
        if self.executor_authority.generation() == 0 {
            return Err(PortError::invalid_data());
        }
        self.clock
            .unix_millis()
            .map(chio_security_types::clock::UnixMillis::get)?;
        Ok(())
    }

    fn ensure_ready(&self) -> PortResult<()> {
        self.clock
            .unix_millis()
            .map(chio_security_types::clock::UnixMillis::get)?;
        if let super::super::response_simulation::ActiveResponseExecutionProfile::DryRun(service) =
            &self.profile
        {
            service.ensure_ready()?;
        }
        let kernel = self.bound_kernel()?;
        self.validate_kernel(kernel.as_ref())
    }

    fn recover_committed(
        &self,
        response_plan: &ResponsePlan,
        dispatch_id: &RecordId,
    ) -> PortResult<Option<AttestedFindingResponseCompletionProof>> {
        if self.execution_mode() != chio_security_types::ResponseExecutionMode::Live {
            return Err(PortError::invalid_data());
        }
        let kernel = self.bound_kernel()?;
        kernel
            .recover_committed_active_response(response_plan, dispatch_id)
            .map_err(map_active_response_kernel_error)?
            .map(|evidence| {
                validated_active_response_completion_proof(response_plan, dispatch_id, evidence)
            })
            .transpose()
    }

    fn resume_dispatch_committed(
        &self,
        response_plan: &ResponsePlan,
        binding: &PreparedActiveResponseDispatchBinding,
    ) -> PortResult<AttestedFindingDispatchCommittedResume> {
        if self.execution_mode() != chio_security_types::ResponseExecutionMode::Live {
            return Err(PortError::invalid_data());
        }
        let kernel = self.bound_kernel()?;
        match kernel
            .resume_dispatch_committed_active_response(response_plan, binding)
            .map_err(map_active_response_kernel_error)?
        {
            DispatchCommittedActiveResponseResume::NotDispatchCommitted => {
                Ok(AttestedFindingDispatchCommittedResume::NotDispatchCommitted)
            }
            DispatchCommittedActiveResponseResume::Completed(evidence) => {
                validated_active_response_completion_proof(
                    response_plan,
                    &binding.dispatch_id,
                    *evidence,
                )
                .map(AttestedFindingDispatchCommittedResume::Completed)
            }
        }
    }

    fn reconstruct_pre_dispatch(
        &self,
        plan: &ReservedAttestedFindingResponsePlan,
        artifacts: AttestedFindingAdmissionArtifacts,
        binding: &PreparedActiveResponseDispatchBinding,
    ) -> PortResult<AttestedFindingPreDispatchReconstruction> {
        if self.execution_mode() != chio_security_types::ResponseExecutionMode::Live {
            return Err(PortError::invalid_data());
        }
        let kernel = self.bound_kernel()?;
        self.validate_kernel(kernel.as_ref())?;
        let expected_artifact_digest = plan
            .admission_artifact_digest()
            .ok_or_else(PortError::integrity_failure)?;
        if &artifacts.canonical_digest(plan.response_plan())? != expected_artifact_digest {
            return Err(PortError::integrity_failure());
        }
        let request = artifacts
            .into_admission_request(plan.response_plan().clone())
            .map_err(map_active_response_kernel_error)?;
        let governed_request = match &request.response_plan().approval_requirement {
            ResponseApprovalRequirement::Automatic => None,
            ResponseApprovalRequirement::Governed { .. } => {
                Some(governed_approval_request_from_native(&request)?)
            }
        };
        let (prepared, governed_approval) = match governed_request {
            None => match kernel
                .reconstruct_pre_dispatch_active_response_admission(&request, binding)
                .map_err(map_active_response_kernel_error)?
            {
                PreDispatchActiveResponseReconstruction::NotPrepared => {
                    return Ok(AttestedFindingPreDispatchReconstruction::NotPrepared);
                }
                PreDispatchActiveResponseReconstruction::Prepared(prepared) => (prepared, None),
            },
            Some(governed_request) => {
                let retained = GovernedApprovalReservation {
                    request: governed_request.clone(),
                    prepared_dispatch_binding: binding.clone(),
                    expires_at_unix_ms: governed_request.proposal_expires_at_unix_ms,
                };
                let verifier = KernelActiveResponseApprovalVerifier::for_reconstruction(
                    kernel.as_ref(),
                    &governed_request,
                    &request,
                );
                let coordinator = ResponseApprovalCoordinator::new(verifier);
                let reconstructed = coordinator
                    .reconstruct(
                        plan.response_plan(),
                        &governed_request,
                        &retained,
                        self.clock
                            .unix_millis()
                            .map(chio_security_types::clock::UnixMillis::get)?,
                    )
                    .map_err(map_approval_coordinator_error)?;
                let Some(reconstructed) = reconstructed else {
                    return Ok(AttestedFindingPreDispatchReconstruction::NotPrepared);
                };
                let prepared = coordinator.verifier().retained_prepared()?;
                (prepared, Some(reconstructed))
            }
        };
        Ok(AttestedFindingPreDispatchReconstruction::Prepared(
            Box::new(PreparedAttestedFindingResponse::Kernel(Box::new(
                KernelPreparedAttestedFindingResponse {
                    request,
                    prepared,
                    governed_approval,
                },
            ))),
        ))
    }

    fn terminate_never_committed(
        &self,
        response_plan: &ResponsePlan,
        binding: &PreparedActiveResponseDispatchBinding,
        current_artifacts: Option<&AttestedFindingAdmissionArtifacts>,
    ) -> PortResult<()> {
        if self.execution_mode() != chio_security_types::ResponseExecutionMode::Live {
            return Err(PortError::invalid_data());
        }
        let kernel = self.bound_kernel()?;
        let current_request = current_artifacts
            .cloned()
            .map(|artifacts| artifacts.into_admission_request(response_plan.clone()))
            .transpose()
            .map_err(map_active_response_kernel_error)?;
        kernel
            .terminate_never_committed_active_response(
                response_plan,
                binding,
                current_request.as_ref(),
            )
            .map_err(map_active_response_kernel_error)
    }

    fn prepare_admission(
        &self,
        plan: &ReservedAttestedFindingResponsePlan,
        artifacts: AttestedFindingAdmissionArtifacts,
    ) -> PortResult<PreparedAttestedFindingResponse> {
        if self.execution_mode() != chio_security_types::ResponseExecutionMode::Live {
            return Err(PortError::invalid_data());
        }
        let kernel = self.bound_kernel()?;
        self.validate_kernel(kernel.as_ref())?;
        let expected_artifact_digest = plan
            .admission_artifact_digest()
            .ok_or_else(PortError::integrity_failure)?;
        if &artifacts.canonical_digest(plan.response_plan())? != expected_artifact_digest {
            return Err(PortError::integrity_failure());
        }
        let request = artifacts
            .into_admission_request(plan.response_plan().clone())
            .map_err(map_active_response_kernel_error)?;
        let governed_request = match &request.response_plan().approval_requirement {
            ResponseApprovalRequirement::Automatic => None,
            ResponseApprovalRequirement::Governed { .. } => {
                Some(governed_approval_request_from_native(&request)?)
            }
        };
        let (prepared, governed_approval) = match governed_request {
            None => (
                kernel
                    .prepare_active_response_admission(&request)
                    .map_err(map_active_response_kernel_error)?,
                None,
            ),
            Some(governed_request) => {
                let verifier = KernelActiveResponseApprovalVerifier::for_prepare(
                    kernel.as_ref(),
                    &governed_request,
                    &request,
                );
                let coordinator = ResponseApprovalCoordinator::new(verifier);
                let reservation = coordinator
                    .prepare(
                        plan.response_plan(),
                        &governed_request,
                        self.clock
                            .unix_millis()
                            .map(chio_security_types::clock::UnixMillis::get)?,
                    )
                    .map_err(map_approval_coordinator_error)?;
                let prepared = coordinator.verifier().retained_prepared()?;
                (prepared, Some(reservation))
            }
        };
        Ok(PreparedAttestedFindingResponse::Kernel(Box::new(
            KernelPreparedAttestedFindingResponse {
                request,
                prepared,
                governed_approval,
            },
        )))
    }

    fn cancel_prepared(
        &self,
        plan: &ReservedAttestedFindingResponsePlan,
        prepared: &PreparedAttestedFindingResponse,
    ) -> PortResult<()> {
        if self.execution_mode() != chio_security_types::ResponseExecutionMode::Live {
            return Err(PortError::invalid_data());
        }
        let kernel = self.bound_kernel()?;
        self.validate_kernel(kernel.as_ref())?;
        let prepared = prepared.kernel_prepared()?;
        match (
            &plan.response_plan().approval_requirement,
            &prepared.governed_approval,
        ) {
            (ResponseApprovalRequirement::Automatic, None) => {
                if !matches!(
                    &prepared.prepared,
                    PreparedActiveResponseAdmission::Automatic(_)
                ) {
                    return Err(PortError::integrity_failure());
                }
                Ok(())
            }
            (ResponseApprovalRequirement::Governed { .. }, Some(reservation)) => {
                let governed_request = governed_approval_request_from_native(&prepared.request)?;
                if governed_request != reservation.request {
                    return Err(PortError::integrity_failure());
                }
                let verifier = KernelActiveResponseApprovalVerifier::for_cancel(
                    kernel.as_ref(),
                    &governed_request,
                    &prepared.request,
                    prepared.prepared.clone(),
                );
                ResponseApprovalCoordinator::new(verifier)
                    .cancel(plan.response_plan(), reservation)
                    .map_err(map_approval_coordinator_error)
            }
            _ => Err(PortError::integrity_failure()),
        }
    }

    fn execute_prepared(
        &self,
        plan: &ReservedAttestedFindingResponsePlan,
        prepared: PreparedAttestedFindingResponse,
    ) -> PortResult<AttestedFindingResponseCompletionProof> {
        if self.execution_mode() != chio_security_types::ResponseExecutionMode::Live {
            return Err(PortError::invalid_data());
        }
        let kernel = self.bound_kernel()?;
        self.validate_kernel(kernel.as_ref())?;
        let expected_dispatch_id = prepared.dispatch_id().clone();
        let (request, prepared, governed_approval) = match prepared {
            PreparedAttestedFindingResponse::Kernel(response) => {
                let KernelPreparedAttestedFindingResponse {
                    request,
                    prepared,
                    governed_approval,
                } = *response;
                (request, prepared, governed_approval)
            }
            #[cfg(test)]
            PreparedAttestedFindingResponse::Synthetic { .. } => {
                return Err(PortError::integrity_failure());
            }
        };
        match (
            &plan.response_plan().approval_requirement,
            governed_approval,
        ) {
            (ResponseApprovalRequirement::Automatic, None) => {}
            (ResponseApprovalRequirement::Governed { .. }, Some(reservation)) => {
                let native_binding = prepared
                    .durable_dispatch_binding(plan.response_plan())
                    .map_err(map_active_response_kernel_error)?;
                if native_binding != reservation.prepared_dispatch_binding {
                    return Err(PortError::integrity_failure());
                }
                let verifier = KernelActiveResponseApprovalVerifier::for_commit(
                    kernel.as_ref(),
                    &reservation.request,
                    &request,
                    prepared.clone(),
                );
                let coordinator = ResponseApprovalCoordinator::new(verifier);
                let committed_binding = coordinator
                    .commit(
                        plan.response_plan(),
                        &reservation,
                        self.clock
                            .unix_millis()
                            .map(chio_security_types::clock::UnixMillis::get)?,
                    )
                    .map_err(map_approval_coordinator_error)?;
                if committed_binding != native_binding {
                    return Err(PortError::integrity_failure());
                }
            }
            _ => return Err(PortError::integrity_failure()),
        }
        let evidence = kernel
            .execute_prepared_active_response(&request, &prepared)
            .map_err(map_active_response_kernel_error)?;
        validated_active_response_completion_proof(
            plan.response_plan(),
            &expected_dispatch_id,
            evidence,
        )
    }
}

pub(super) fn validated_active_response_completion_proof(
    response_plan: &ResponsePlan,
    expected_dispatch_id: &RecordId,
    evidence: ActiveResponseExecutionEvidence,
) -> PortResult<AttestedFindingResponseCompletionProof> {
    if evidence.dispatch_id() != expected_dispatch_id
        || evidence.tenant_id() != &response_plan.tenant_id
        || evidence.action_id() != &response_plan.action_id
        || evidence.plan_hash() != &response_plan.plan_hash
    {
        return Err(PortError::integrity_failure());
    }
    match evidence.outcome() {
        ActiveResponseExecutionOutcome::Activated => {
            if evidence.effects().len() != response_plan.effects.len()
                || response_plan
                    .effects
                    .as_slice()
                    .iter()
                    .zip(evidence.effects())
                    .any(|(planned, applied)| &planned.effect_id != applied.effect_id())
            {
                return Err(PortError::integrity_failure());
            }
        }
        ActiveResponseExecutionOutcome::FailedBeforeAnyEffect => {
            if !evidence.effects().is_empty() {
                return Err(PortError::integrity_failure());
            }
        }
        ActiveResponseExecutionOutcome::RolledBackAfterPartial => {}
    }
    Ok(AttestedFindingResponseCompletionProof {
        dispatch_id: evidence.dispatch_id().clone(),
        outcome: match evidence.outcome() {
            ActiveResponseExecutionOutcome::Activated => {
                AttestedFindingResponseCompletionOutcome::Activated
            }
            ActiveResponseExecutionOutcome::FailedBeforeAnyEffect => {
                AttestedFindingResponseCompletionOutcome::FailedBeforeEffect
            }
            ActiveResponseExecutionOutcome::RolledBackAfterPartial => {
                AttestedFindingResponseCompletionOutcome::RolledBackAfterPartial
            }
        },
        evidence_id: evidence.proof_evidence_id().clone(),
        evidence_body_hash: *evidence.proof_body_hash(),
    })
}

pub(super) fn map_approval_coordinator_error(error: ApprovalCoordinatorError) -> PortError {
    match error {
        ApprovalCoordinatorError::Authority(error) => error,
        ApprovalCoordinatorError::Expired | ApprovalCoordinatorError::InvalidPlan => {
            PortError::invalid_data()
        }
        ApprovalCoordinatorError::AutomaticPlan
        | ApprovalCoordinatorError::InvalidRequest
        | ApprovalCoordinatorError::InvalidAdmissionArtifact(_)
        | ApprovalCoordinatorError::InvalidReservation
        | ApprovalCoordinatorError::Canonical(_) => PortError::integrity_failure(),
    }
}

pub(in crate::security) fn map_active_response_kernel_error(error: KernelError) -> PortError {
    let definitively_never_committed =
        matches!(&error, KernelError::ActiveResponseNeverCommitted(_));
    let retryable = matches!(
        &error,
        KernelError::Internal(_)
            | KernelError::ReceiptPersistence(_)
            | KernelError::RevocationStore(_)
            | KernelError::Overloaded { .. }
            | KernelError::SecurityDispatchOutcomeRecoveryRequired(_)
    );
    let code = match ErrorCode::new(error.report().code) {
        Ok(code) => code,
        Err(_) => return PortError::integrity_failure(),
    };
    if definitively_never_committed && code.as_str() != "active_response.never_committed" {
        return PortError::integrity_failure();
    }
    PortError::new(
        if retryable {
            PortErrorKind::Unavailable
        } else {
            PortErrorKind::InvalidData
        },
        code,
    )
}

#[cfg(test)]
impl KernelPreparedAttestedFindingResponse {
    pub(super) fn test_prepared(&self) -> &PreparedActiveResponseAdmission { &self.prepared }
    pub(super) fn test_governed_approval(&self) -> &Option<GovernedApprovalReservation> { &self.governed_approval }
    pub(super) fn test_request(&self) -> &ActiveResponseAdmissionRequest { &self.request }
}
