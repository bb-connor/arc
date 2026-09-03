use chio_core::capability::governance::{
    GovernedApprovalToken, GovernedResponsePlanIntentBody, CHIO_ACTIVE_RESPONSE_SERVER_ID,
};
use chio_core::crypto::SigningAlgorithm;
use chio_core::receipt::body::ChioReceipt;
use chio_core::receipt::decision::ToolCallAction;
use chio_core::receipt::kinds::{
    BoundaryClass, ObservationOutcome, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel,
};
use chio_core::receipt::security::{
    validate_response_snapshot_lifecycle, ActiveDefenseReceiptBody,
};
use chio_core::{canonical_json_bytes, sha256, Hash};
use chio_security_types::ports::{
    AdmissionArtifactRef, Digest32, EffectId, RecordId, ResponseDispatchApproval,
};
use chio_security_types::{
    PlannedResponseEffect, ResponseApprovalRequirement, ResponseEffectSpec, ResponseMutationRecord,
    ResponsePlan, ResponseSnapshot, ResponseState,
};
use serde::Serialize;

use crate::approval::{ApprovalReservation, ApprovalSetReservationInput};
use crate::security_admission_operation::{
    AdmissionDispatchState, AdmissionOperation, AdmissionOperationCasOutcome,
    AdmissionOperationCompareAndSwap, AdmissionOperationCreateOutcome, AdmissionOperationKind,
    AdmissionOperationState, PreparedAdmissionOperation, ReplayReservationState,
};
use crate::threshold_approval::{
    verify_threshold_approval_set, ThresholdApprovalProposal, ThresholdApprovalVerificationInput,
    VerifiedThresholdApprovalSet,
};

use super::active_response_admission::{
    ActiveResponseAuthorizationRequest, VerifiedActiveResponseBindings,
};
use super::active_response_artifact::ActiveResponseArtifactAuthorityAttestation;
use super::active_response_operation_binding::{
    active_response_dispatch_operation_version, build_active_response_operation_anchor,
    derive_active_response_operation_request_binding_hash, ActiveResponseOperationAnchor,
};
use super::active_response_policy::VerifiedActiveResponseRequirement;
use super::active_response_proof::{
    active_response_effect_commitment, active_response_execution_dispatch_binding,
    active_response_expected_effect_outcome, active_response_response_binding,
    verify_active_response_dispatch_authorization,
};
use super::admission_cleanup::ActiveResponseOperationAnchorJournalError;
use super::{current_unix_timestamp_ms, ChioKernel, KernelCryptoFloor, KernelError};
use super::{
    derive_active_response_dispatch_id, ActiveResponseExecutionApproval,
    ActiveResponseExecutionEvidence, ActiveResponseExecutionOutcome,
    ActiveResponseExecutionRequest, ActiveResponseExecutionRequestParts,
    ActiveResponseExecutorAuthorityIdentity, ActiveResponseExecutorError,
};

const ACTIVE_RESPONSE_APPROVAL_TOOL_NAME: &str = "governed_response_plan";
const ACTIVE_RESPONSE_COORDINATOR_LEASE_EPOCH: u64 = 1;
const AFFECTED_SET_HASH_DOMAIN: &[u8] = b"chio.response-affected-set.v1\0";
const EFFECT_ID_DOMAIN: &[u8] = b"chio.response-effect.v1\0";

/// Complete immutable envelope presented to the active-response admission seam.
#[derive(Clone, Debug)]
pub struct ActiveResponseAdmissionRequest {
    response_plan: ResponsePlan,
    authorization: ActiveResponseAuthorizationRequest,
    admission_artifact_ref: AdmissionArtifactRef,
    artifact_authority_attestation: ActiveResponseArtifactAuthorityAttestation,
    threshold_proposal: Option<ThresholdApprovalProposal>,
    approval_tokens: Vec<GovernedApprovalToken>,
}

impl ActiveResponseAdmissionRequest {
    pub fn new(
        response_plan: ResponsePlan,
        authorization: ActiveResponseAuthorizationRequest,
        admission_artifact_ref: AdmissionArtifactRef,
        artifact_authority_attestation: ActiveResponseArtifactAuthorityAttestation,
        threshold_proposal: Option<ThresholdApprovalProposal>,
        approval_tokens: Vec<GovernedApprovalToken>,
    ) -> Result<Self, KernelError> {
        if response_plan.authorization_body() != *authorization.plan_body() {
            return Err(active_response_denied(
                "full response plan does not reproduce the compact authorization body",
            ));
        }
        Ok(Self {
            response_plan,
            authorization,
            admission_artifact_ref,
            artifact_authority_attestation,
            threshold_proposal,
            approval_tokens,
        })
    }

    #[must_use]
    pub const fn response_plan(&self) -> &ResponsePlan {
        &self.response_plan
    }

    #[must_use]
    pub const fn authorization(&self) -> &ActiveResponseAuthorizationRequest {
        &self.authorization
    }

    #[must_use]
    pub const fn admission_artifact_ref(&self) -> &AdmissionArtifactRef {
        &self.admission_artifact_ref
    }

    #[must_use]
    pub const fn artifact_authority_attestation(
        &self,
    ) -> &ActiveResponseArtifactAuthorityAttestation {
        &self.artifact_authority_attestation
    }

    #[must_use]
    pub const fn threshold_proposal(&self) -> Option<&ThresholdApprovalProposal> {
        self.threshold_proposal.as_ref()
    }

    pub(super) const fn threshold_proposal_option(&self) -> &Option<ThresholdApprovalProposal> {
        &self.threshold_proposal
    }

    #[must_use]
    pub fn approval_tokens(&self) -> &[GovernedApprovalToken] {
        &self.approval_tokens
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AutomaticActiveResponsePermit {
    pub(super) dispatch_id: RecordId,
    pub(super) request_id: String,
    pub(super) plan_body_hash: String,
    pub(super) authorization_capability_hash: String,
    pub(super) governed_intent_hash: String,
    pub(super) policy_decision_hash: String,
    pub(super) executor_authority_id: String,
    pub(super) executor_authority_generation: u64,
    pub(super) authorized_at_unix_ms: u64,
    pub(super) expires_at_unix_ms: u64,
}

impl AutomaticActiveResponsePermit {
    #[must_use]
    pub const fn dispatch_id(&self) -> &RecordId {
        &self.dispatch_id
    }

    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    #[must_use]
    pub fn plan_body_hash(&self) -> &str {
        &self.plan_body_hash
    }

    #[must_use]
    pub fn authorization_capability_hash(&self) -> &str {
        &self.authorization_capability_hash
    }

    #[must_use]
    pub fn governed_intent_hash(&self) -> &str {
        &self.governed_intent_hash
    }

    #[must_use]
    pub fn policy_decision_hash(&self) -> &str {
        &self.policy_decision_hash
    }

    #[must_use]
    pub fn executor_authority_id(&self) -> &str {
        &self.executor_authority_id
    }

    #[must_use]
    pub const fn executor_authority_generation(&self) -> u64 {
        self.executor_authority_generation
    }

    #[must_use]
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedActiveResponseReservation {
    pub(super) operation: Box<AdmissionOperation>,
    pub(super) approval_set: Box<ApprovalSetReservationInput>,
    pub(super) policy_decision_hash: String,
    pub(super) authorization_capability_hash: String,
    pub(super) governed_intent_hash: String,
    pub(super) executor_authority_id: String,
    pub(super) executor_authority_generation: u64,
    pub(super) authorized_at_unix_ms: u64,
    pub(super) dispatch_operation_version: u64,
    pub(super) dispatch_id: RecordId,
}

impl GovernedActiveResponseReservation {
    #[must_use]
    pub const fn dispatch_id(&self) -> &RecordId {
        &self.dispatch_id
    }

    #[must_use]
    pub fn operation_id(&self) -> &str {
        self.operation.operation_id()
    }

    #[must_use]
    pub fn approval_set_hash(&self) -> &str {
        self.approval_set.approval_set_hash()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreparedActiveResponseAdmission {
    Automatic(AutomaticActiveResponsePermit),
    Governed(GovernedActiveResponseReservation),
}

impl PreparedActiveResponseAdmission {
    #[must_use]
    pub const fn dispatch_id(&self) -> &RecordId {
        match self {
            Self::Automatic(permit) => permit.dispatch_id(),
            Self::Governed(reservation) => reservation.dispatch_id(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ActiveResponseDispatchPermit {
    pub(super) operation: AdmissionOperation,
    pub(super) recovery: bool,
}

pub(super) struct VerifiedGovernedActiveResponse {
    pub(super) operation: Box<AdmissionOperation>,
    pub(super) approval_set: Box<ApprovalSetReservationInput>,
    pub(super) policy_decision_hash: String,
    pub(super) authorized_at_unix_ms: u64,
}

pub(super) enum VerifiedActiveResponseAdmission {
    Automatic(AutomaticActiveResponsePermit),
    Governed(VerifiedGovernedActiveResponse),
}

pub(super) struct ActiveResponseCasResult {
    pub(super) operation: AdmissionOperation,
    pub(super) applied: bool,
}

impl ChioKernel {
    pub fn prepare_active_response_admission(
        &self,
        request: &ActiveResponseAdmissionRequest,
    ) -> Result<PreparedActiveResponseAdmission, KernelError> {
        let verified_admission =
            self.verify_active_response_admission_at(request, current_unix_timestamp_ms())?;
        self.prepare_verified_active_response_admission(request, verified_admission)
    }

    pub(super) fn prepare_verified_active_response_admission(
        &self,
        request: &ActiveResponseAdmissionRequest,
        verified_admission: VerifiedActiveResponseAdmission,
    ) -> Result<PreparedActiveResponseAdmission, KernelError> {
        match verified_admission {
            VerifiedActiveResponseAdmission::Automatic(permit) => {
                Ok(PreparedActiveResponseAdmission::Automatic(permit))
            }
            VerifiedActiveResponseAdmission::Governed(mut verified) => {
                self.validate_active_response_coordinator_profiles()?;
                let mut operation = self.create_active_response_operation(&verified.operation)?;
                let executor_authority = self
                    .active_response_executor_identity()
                    .map_err(|error| active_response_denied(error.to_string()))?;
                if operation.coordinator_authority_id() != executor_authority.authority_id() {
                    return Err(active_response_denied(
                        "persisted active-response executor authority no longer matches",
                    ));
                }
                let governed_intent_hash = request
                    .authorization()
                    .governed_intent()
                    .binding_hash()
                    .map_err(|error| {
                        active_response_denied(format!(
                            "active-response governed intent hashing failed: {error}"
                        ))
                    })?;
                let anchor = build_active_response_operation_anchor(
                    request.response_plan(),
                    &executor_authority,
                    verified.authorized_at_unix_ms,
                    operation.authorization_capability_hash(),
                    &governed_intent_hash,
                    &verified.policy_decision_hash,
                    verified.approval_set.approval_set_hash(),
                )?;
                let retained_anchor = match self.journal_active_response_operation_anchor(
                    &operation,
                    anchor,
                    &verified.approval_set,
                ) {
                    Ok(anchor) => anchor,
                    Err(ActiveResponseOperationAnchorJournalError::Kernel(error)) => {
                        match self.claim_pre_dispatch_compensation(
                            operation.operation_id(),
                            &error.to_string(),
                        ) {
                            Ok(Some(_)) => return Err(error),
                            Ok(None) => {
                                return Err(active_response_internal(format!(
                                    "active-response preparation failed without a compensable operation: {error}"
                                )))
                            }
                            Err(compensation_error) => {
                                return Err(active_response_internal(format!(
                                    "active-response preparation failed ({error}); compensation failed: {compensation_error}"
                                )))
                            }
                        }
                    }
                    Err(ActiveResponseOperationAnchorJournalError::Conflict) => {
                        let denial = active_response_denied(
                            "persisted active-response preparation is stale",
                        );
                        if matches!(
                            operation.state(),
                            AdmissionOperationState::Prepared
                                | AdmissionOperationState::ApprovalReserved
                        ) {
                            let _ = self.claim_pre_dispatch_compensation(
                                operation.operation_id(),
                                &denial.to_string(),
                            )?;
                        }
                        return Err(denial);
                    }
                };
                verified.authorized_at_unix_ms = retained_anchor.authorized_at_unix_ms;
                if operation.state() == AdmissionOperationState::ApprovalReserved {
                    let operation_store =
                        self.admission_operation_store.as_ref().ok_or_else(|| {
                            active_response_internal(
                                "durable active-response operation store is not installed",
                            )
                        })?;
                    if let Some(committed) = self.reconcile_governed_active_response_commit(
                        operation_store.as_ref(),
                        self.approval_store.as_deref(),
                        &operation,
                    )? {
                        operation = committed;
                    }
                }
                match operation.state() {
                    AdmissionOperationState::Prepared
                    | AdmissionOperationState::ApprovalReserved => {
                        if let Err(error) = self.reserve_active_response_approval_set(
                            operation.operation_id(),
                            &verified.approval_set,
                        ) {
                            if self
                                .claim_pre_dispatch_compensation(
                                    operation.operation_id(),
                                    &error.to_string(),
                                )?
                                .is_none()
                            {
                                return Err(active_response_internal(
                                    "active-response approval failure lost the compensation race",
                                ));
                            }
                            return Err(error);
                        }
                    }
                    AdmissionOperationState::DispatchCommitted
                    | AdmissionOperationState::Completed => {
                        self.commit_active_response_approval_set(
                            operation.operation_id(),
                            &verified.approval_set,
                        )?;
                    }
                    _ => {}
                }

                for _ in 0..8 {
                    operation = match operation.state() {
                        AdmissionOperationState::Prepared => {
                            self.active_response_cas(
                                &operation,
                                AdmissionOperationState::ApprovalReserved,
                                AdmissionDispatchState::NotStarted,
                                None,
                            )?
                            .operation
                        }
                        AdmissionOperationState::ApprovalReserved
                        | AdmissionOperationState::DispatchCommitted
                        | AdmissionOperationState::Completed => break,
                        AdmissionOperationState::CompensationPending
                        | AdmissionOperationState::CompensatedBeforeDispatch => {
                            if !self
                                .recover_compensated_admission_operation(operation.operation_id())?
                            {
                                return Err(active_response_internal(
                                    "active-response cleanup is owned by another recovery worker",
                                ));
                            }
                            return Err(active_response_denied(
                                "active-response admission operation was compensated",
                            ));
                        }
                        AdmissionOperationState::OutcomeUnknownAfterDispatch => {
                            return Err(active_response_denied(
                                "active-response admission outcome requires reconciliation",
                            ));
                        }
                        AdmissionOperationState::BrokerAttemptRegistered
                        | AdmissionOperationState::BudgetAuthorized
                        | AdmissionOperationState::DelegatedBudgetReserved
                        | AdmissionOperationState::PaymentAuthorized
                        | AdmissionOperationState::ReadyToDispatch
                        | AdmissionOperationState::CapturePending
                        | AdmissionOperationState::CallerReservationCapturePending
                        | AdmissionOperationState::CallerReserved => {
                            return Err(active_response_internal(
                                "governed active response entered a tool-dispatch-only state",
                            ));
                        }
                    };
                }
                if !matches!(
                    operation.state(),
                    AdmissionOperationState::ApprovalReserved
                        | AdmissionOperationState::DispatchCommitted
                        | AdmissionOperationState::Completed
                ) {
                    return Err(active_response_internal(
                        "active-response reservation did not converge",
                    ));
                }
                let dispatch_operation_version =
                    active_response_dispatch_operation_version(&operation)?;
                let execution = build_active_response_execution_request(
                    request,
                    executor_authority,
                    &verified.policy_decision_hash,
                    verified.authorized_at_unix_ms,
                    ActiveResponseExecutionApproval::Governed {
                        admission_operation_id: operation.operation_id().to_string(),
                        admission_operation_version: dispatch_operation_version,
                        approval_set_hash: verified.approval_set.approval_set_hash().to_string(),
                    },
                )?;
                Ok(PreparedActiveResponseAdmission::Governed(
                    GovernedActiveResponseReservation {
                        operation: Box::new(operation),
                        approval_set: verified.approval_set,
                        policy_decision_hash: verified.policy_decision_hash,
                        authorization_capability_hash: execution
                            .authorization_capability_hash()
                            .to_string(),
                        governed_intent_hash: execution.governed_intent_hash().to_string(),
                        executor_authority_id: execution.executor_authority_id().to_string(),
                        executor_authority_generation: execution.executor_authority_generation(),
                        authorized_at_unix_ms: execution.authorized_at_unix_ms(),
                        dispatch_operation_version,
                        dispatch_id: execution.dispatch_id().clone(),
                    },
                ))
            }
        }
    }

    /// Commits a governed prepared admission before its first idempotent response effect.
    ///
    /// This entry point is intended for trusted approval-verifier adapters. Automatic
    /// preparations are not approval reservations and therefore fail closed here.
    pub fn commit_prepared_active_response_admission(
        &self,
        request: &ActiveResponseAdmissionRequest,
        prepared: &PreparedActiveResponseAdmission,
    ) -> Result<(), KernelError> {
        match prepared {
            PreparedActiveResponseAdmission::Automatic(_) => Err(active_response_denied(
                "approval-only active-response commitment requires a governed preparation",
            )),
            PreparedActiveResponseAdmission::Governed(reservation) => {
                let installed = self.active_response_executor.as_ref().ok_or_else(|| {
                    active_response_internal("active-response executor authority is not installed")
                })?;
                let _dispatch_gate = installed.dispatch_gate.lock().map_err(|_| {
                    active_response_internal("active-response executor dispatch gate is poisoned")
                })?;
                self.commit_active_response_dispatch(request, reservation)?;
                Ok(())
            }
        }
    }

    /// Cancels one exact governed preparation before dispatch commitment.
    ///
    /// Automatic preparations have no approval reservation and fail closed.
    pub fn cancel_prepared_active_response_admission(
        &self,
        prepared: &PreparedActiveResponseAdmission,
        reason: &str,
    ) -> Result<(), KernelError> {
        match prepared {
            PreparedActiveResponseAdmission::Automatic(_) => Err(active_response_denied(
                "approval-only active-response cancellation requires a governed preparation",
            )),
            PreparedActiveResponseAdmission::Governed(reservation) => {
                let installed = self.active_response_executor.as_ref().ok_or_else(|| {
                    active_response_internal("active-response executor authority is not installed")
                })?;
                let _dispatch_gate = installed.dispatch_gate.lock().map_err(|_| {
                    active_response_internal("active-response executor dispatch gate is poisoned")
                })?;
                self.compensate_active_response_before_dispatch(reservation, reason)
            }
        }
    }

    pub(crate) fn commit_active_response_dispatch(
        &self,
        request: &ActiveResponseAdmissionRequest,
        reservation: &GovernedActiveResponseReservation,
    ) -> Result<ActiveResponseDispatchPermit, KernelError> {
        self.validate_active_response_coordinator_profiles()?;
        let mut operation = self.load_active_response_operation(reservation.operation_id())?;
        if !operation.has_same_prepared_binding(&reservation.operation) {
            return Err(active_response_internal(
                "persisted active-response operation changed identity",
            ));
        }
        let committed_recovery = matches!(
            operation.state(),
            AdmissionOperationState::DispatchCommitted | AdmissionOperationState::Completed
        );
        if !committed_recovery {
            let now_unix_ms = current_unix_timestamp_ms();
            let verified = match self.verify_active_response_admission_with_authorized_at(
                request,
                now_unix_ms,
                reservation.authorized_at_unix_ms,
            ) {
                Ok(VerifiedActiveResponseAdmission::Governed(verified)) => verified,
                Ok(VerifiedActiveResponseAdmission::Automatic(_)) => {
                    let error = active_response_denied(
                        "governed reservation no longer resolves to governed approval",
                    );
                    self.compensate_active_response_before_dispatch(
                        reservation,
                        &error.to_string(),
                    )?;
                    return Err(error);
                }
                Err(error) => {
                    self.compensate_active_response_before_dispatch(
                        reservation,
                        &error.to_string(),
                    )?;
                    return Err(error);
                }
            };
            if verified.operation.operation_id() != reservation.operation.operation_id()
                || !verified
                    .operation
                    .has_same_prepared_binding(&reservation.operation)
                || verified.approval_set != reservation.approval_set
                || verified.policy_decision_hash != reservation.policy_decision_hash
            {
                let error = active_response_denied(
                    "commit-time authorization does not match the reserved active response",
                );
                self.compensate_active_response_before_dispatch(reservation, &error.to_string())?;
                return Err(error);
            }
        }
        let executor_authority = self
            .active_response_executor_identity()
            .map_err(|error| active_response_internal(error.to_string()))?;
        let expected_anchor = build_active_response_operation_anchor(
            request.response_plan(),
            &executor_authority,
            reservation.authorized_at_unix_ms,
            &reservation.authorization_capability_hash,
            &reservation.governed_intent_hash,
            &reservation.policy_decision_hash,
            reservation.approval_set.approval_set_hash(),
        )?;
        if self.load_active_response_operation_anchor(&operation)? != expected_anchor {
            return Err(active_response_internal(
                "persisted active-response operation anchor changed before dispatch",
            ));
        }
        if matches!(
            operation.state(),
            AdmissionOperationState::Prepared
                | AdmissionOperationState::ApprovalReserved
                | AdmissionOperationState::DispatchCommitted
                | AdmissionOperationState::Completed
        ) && active_response_dispatch_operation_version(&operation)?
            != reservation.dispatch_operation_version
        {
            return Err(active_response_internal(
                "persisted active-response dispatch version changed",
            ));
        }

        for _ in 0..8 {
            match operation.state() {
                AdmissionOperationState::Prepared => {
                    self.reserve_active_response_approval_set(
                        operation.operation_id(),
                        &reservation.approval_set,
                    )?;
                    operation = self
                        .active_response_cas(
                            &operation,
                            AdmissionOperationState::ApprovalReserved,
                            AdmissionDispatchState::NotStarted,
                            None,
                        )?
                        .operation;
                }
                AdmissionOperationState::ApprovalReserved => {
                    if self.load_active_response_operation_anchor(&operation)? != expected_anchor {
                        return Err(active_response_internal(
                            "persisted active-response operation anchor changed before dispatch",
                        ));
                    }
                    self.commit_active_response_approval_set(
                        operation.operation_id(),
                        &reservation.approval_set,
                    )?;
                    let committed = self.active_response_cas(
                        &operation,
                        AdmissionOperationState::DispatchCommitted,
                        AdmissionDispatchState::Committed,
                        None,
                    )?;
                    if committed.operation.state() == AdmissionOperationState::DispatchCommitted {
                        return Ok(ActiveResponseDispatchPermit {
                            operation: committed.operation,
                            recovery: !committed.applied,
                        });
                    }
                    operation = committed.operation;
                }
                AdmissionOperationState::DispatchCommitted => {
                    self.commit_active_response_approval_set(
                        operation.operation_id(),
                        &reservation.approval_set,
                    )?;
                    return Ok(ActiveResponseDispatchPermit {
                        operation,
                        recovery: true,
                    });
                }
                AdmissionOperationState::Completed => {
                    let store = self.admission_operation_store.as_ref().ok_or_else(|| {
                        active_response_internal(
                            "active-response admission operation store is unavailable",
                        )
                    })?;
                    self.validate_terminal_receipt_binding_with_store(store.as_ref(), &operation)?;
                    self.commit_active_response_approval_set(
                        operation.operation_id(),
                        &reservation.approval_set,
                    )?;
                    return Ok(ActiveResponseDispatchPermit {
                        operation,
                        recovery: true,
                    });
                }
                AdmissionOperationState::CompensationPending
                | AdmissionOperationState::CompensatedBeforeDispatch => {
                    if !self.recover_compensated_admission_operation(operation.operation_id())? {
                        return Err(active_response_internal(
                            "active-response cleanup is owned by another recovery worker",
                        ));
                    }
                    return Err(active_response_denied(
                        "compensated active-response admission cannot dispatch",
                    ));
                }
                AdmissionOperationState::OutcomeUnknownAfterDispatch => {
                    return Err(active_response_denied(
                        "unknown active-response outcome cannot dispatch again",
                    ));
                }
                AdmissionOperationState::BrokerAttemptRegistered
                | AdmissionOperationState::BudgetAuthorized
                | AdmissionOperationState::DelegatedBudgetReserved
                | AdmissionOperationState::PaymentAuthorized
                | AdmissionOperationState::ReadyToDispatch
                | AdmissionOperationState::CapturePending
                | AdmissionOperationState::CallerReservationCapturePending
                | AdmissionOperationState::CallerReserved => {
                    return Err(active_response_internal(
                        "governed active response entered a tool-dispatch-only state",
                    ));
                }
            }
        }
        Err(active_response_internal(
            "active-response dispatch commitment did not converge",
        ))
    }

    pub fn execute_prepared_active_response(
        &self,
        request: &ActiveResponseAdmissionRequest,
        prepared: &PreparedActiveResponseAdmission,
    ) -> Result<ActiveResponseExecutionEvidence, KernelError> {
        let installed = self.active_response_executor.as_ref().ok_or_else(|| {
            active_response_internal("active-response executor authority is not installed")
        })?;
        let _dispatch_gate = installed.dispatch_gate.lock().map_err(|_| {
            active_response_internal("active-response executor dispatch gate is poisoned")
        })?;
        match prepared {
            PreparedActiveResponseAdmission::Automatic(expected) => {
                let validation_now_unix_ms = current_unix_timestamp_ms();
                let fresh = match self.verify_active_response_admission_with_authorized_at(
                    request,
                    validation_now_unix_ms,
                    expected.authorized_at_unix_ms,
                )? {
                    VerifiedActiveResponseAdmission::Automatic(fresh) => fresh,
                    VerifiedActiveResponseAdmission::Governed(_) => {
                        return Err(active_response_denied(
                            "automatic active response now requires governed approval",
                        ));
                    }
                };
                let executor_authority = self
                    .active_response_executor_identity()
                    .map_err(|error| active_response_denied(error.to_string()))?;
                if &fresh != expected {
                    return Err(active_response_denied(
                        "automatic active-response permit is stale",
                    ));
                }
                if executor_authority.authority_id() != expected.executor_authority_id()
                    || executor_authority.generation() != expected.executor_authority_generation()
                {
                    return Err(active_response_denied(
                        "automatic active-response executor authority changed",
                    ));
                }
                let execution = build_active_response_execution_request(
                    request,
                    executor_authority,
                    expected.policy_decision_hash(),
                    expected.authorized_at_unix_ms,
                    ActiveResponseExecutionApproval::Automatic,
                )?;
                if execution.dispatch_id() != expected.dispatch_id() {
                    return Err(active_response_internal(
                        "automatic active-response dispatch identifier changed",
                    ));
                }
                self.execute_active_response_with_authority(&execution)
            }
            PreparedActiveResponseAdmission::Governed(reservation) => {
                let permit = self.commit_active_response_dispatch(request, reservation)?;
                let executor_authority = self
                    .active_response_executor_identity()
                    .map_err(|error| active_response_denied(error.to_string()))?;
                if permit.operation.coordinator_authority_id() != executor_authority.authority_id()
                {
                    return Err(active_response_denied(
                        "governed active-response executor authority changed after commitment",
                    ));
                }
                let execution = build_active_response_execution_request(
                    request,
                    executor_authority,
                    &reservation.policy_decision_hash,
                    reservation.authorized_at_unix_ms,
                    ActiveResponseExecutionApproval::Governed {
                        admission_operation_id: permit.operation.operation_id().to_string(),
                        admission_operation_version: reservation.dispatch_operation_version,
                        approval_set_hash: reservation.approval_set_hash().to_string(),
                    },
                )?;
                if execution.dispatch_id() != reservation.dispatch_id() {
                    return Err(active_response_internal(
                        "governed active-response dispatch identifier changed",
                    ));
                }
                let evidence = self.execute_active_response_with_authority(&execution)?;
                self.complete_active_response_dispatch(&permit, &execution, &evidence)?;
                Ok(evidence)
            }
        }
    }

    pub fn cancel_active_response_admission(
        &self,
        reservation: &GovernedActiveResponseReservation,
        reason: &str,
    ) -> Result<(), KernelError> {
        let installed = self.active_response_executor.as_ref().ok_or_else(|| {
            active_response_internal("active-response executor authority is not installed")
        })?;
        let _dispatch_gate = installed.dispatch_gate.lock().map_err(|_| {
            active_response_internal("active-response executor dispatch gate is poisoned")
        })?;
        self.compensate_active_response_before_dispatch(reservation, reason)
    }

    pub(super) fn require_definitive_active_response_denial(
        &self,
        request: &ActiveResponseAdmissionRequest,
    ) -> Result<(), KernelError> {
        let now_unix_ms = current_unix_timestamp_ms();
        let denial = match self.verify_active_response_admission_at(request, now_unix_ms) {
            Ok(_) => {
                return Err(active_response_denied(
                    "current live admission remains valid and cannot be terminated",
                ))
            }
            Err(error) => error,
        };
        if matches!(
            &denial,
            KernelError::CapabilityRevoked(_) | KernelError::DelegationChainRevoked(_)
        ) {
            return Ok(());
        }
        let proposal_window_expired = request
            .threshold_proposal()
            .map(|proposal| {
                proposal
                    .body()
                    .proposal_deadline
                    .checked_mul(1_000)
                    .ok_or_else(|| {
                        active_response_internal(
                            "active-response threshold proposal deadline overflowed milliseconds",
                        )
                    })
                    .map(|deadline_unix_ms| now_unix_ms >= deadline_unix_ms)
            })
            .transpose()?
            .unwrap_or(false);
        let mut approval_token_window_expired = false;
        for token in request.approval_tokens() {
            let expires_at_unix_ms = token.expires_at.checked_mul(1_000).ok_or_else(|| {
                active_response_internal(
                    "active-response approval token expiry overflowed milliseconds",
                )
            })?;
            if now_unix_ms >= expires_at_unix_ms {
                approval_token_window_expired = true;
                break;
            }
        }
        let immutable_window_expired = now_unix_ms >= request.response_plan.expires_at_unix_ms
            || now_unix_ms >= request.response_plan.operator_capability.expires_at_unix_ms
            || now_unix_ms
                >= request
                    .authorization
                    .submission_proof()
                    .body
                    .expires_at_unix_ms
            || now_unix_ms
                >= request
                    .artifact_authority_attestation
                    .body
                    .expires_at_unix_ms
            || proposal_window_expired
            || approval_token_window_expired;
        if immutable_window_expired && matches!(&denial, KernelError::GovernedTransactionDenied(_))
        {
            return Ok(());
        }
        Err(active_response_internal(format!(
            "current live admission denial is not definitive: {denial}"
        )))
    }

    pub(super) fn complete_active_response_dispatch(
        &self,
        permit: &ActiveResponseDispatchPermit,
        execution: &ActiveResponseExecutionRequest,
        evidence: &ActiveResponseExecutionEvidence,
    ) -> Result<(), KernelError> {
        validate_active_response_execution_evidence(execution, evidence)?;
        let current = self.load_active_response_operation(permit.operation.operation_id())?;
        if current.state() == AdmissionOperationState::Completed {
            let store = self.admission_operation_store.as_ref().ok_or_else(|| {
                active_response_internal("active-response admission operation store is unavailable")
            })?;
            self.validate_terminal_receipt_binding_with_store(store.as_ref(), &current)?;
            return Ok(());
        }
        if current.state() != AdmissionOperationState::DispatchCommitted {
            return Err(active_response_internal(
                "active-response completion requires a dispatch commitment",
            ));
        }
        let store = self.admission_operation_store.as_ref().ok_or_else(|| {
            active_response_internal("active-response admission operation store is unavailable")
        })?;
        let completed = self.finalize_active_response_completion_terminal_receipt(
            store.as_ref(),
            &current,
            evidence.completion_receipt(),
        )?;
        if completed.state() != AdmissionOperationState::Completed {
            return Err(active_response_internal(
                "active-response completion and signed receipt were not persisted",
            ));
        }
        Ok(())
    }

    pub(super) fn execute_active_response_with_authority(
        &self,
        execution: &ActiveResponseExecutionRequest,
    ) -> Result<ActiveResponseExecutionEvidence, KernelError> {
        let installed = self.active_response_executor.as_ref().ok_or_else(|| {
            active_response_internal("active-response executor authority is not installed")
        })?;
        installed.authority.ensure_ready().map_err(|error| {
            active_response_internal(format!(
                "active-response executor authority is not ready: {error}"
            ))
        })?;
        if installed.identity != *execution.executor_authority()
            || installed.authority.identity() != installed.identity
        {
            return Err(active_response_denied(
                "active-response executor authority identity is stale",
            ));
        }
        let evidence = installed
            .authority
            .execute_active_response(execution)
            .map_err(|error| match error {
                ActiveResponseExecutorError::RejectedBeforeCommit(reason) => {
                    active_response_denied(format!(
                        "active-response executor rejected dispatch before commit: {reason}"
                    ))
                }
                ActiveResponseExecutorError::NotReady(reason) => active_response_internal(format!(
                    "active-response executor became unavailable: {reason}"
                )),
                ActiveResponseExecutorError::OutcomeUnknown(reason) => active_response_internal(
                    format!("active-response executor outcome requires retry: {reason}"),
                ),
            })?;
        if installed.authority.identity() != installed.identity {
            return Err(active_response_internal(
                "active-response executor authority identity changed during execution",
            ));
        }
        validate_active_response_execution_evidence(execution, &evidence)?;
        Ok(evidence)
    }

    fn verify_active_response_admission_at(
        &self,
        request: &ActiveResponseAdmissionRequest,
        now_unix_ms: u64,
    ) -> Result<VerifiedActiveResponseAdmission, KernelError> {
        self.verify_active_response_admission_with_authorized_at(request, now_unix_ms, now_unix_ms)
    }

    pub(super) fn verify_active_response_admission_with_authorized_at(
        &self,
        request: &ActiveResponseAdmissionRequest,
        validation_now_unix_ms: u64,
        stable_authorized_at_unix_ms: u64,
    ) -> Result<VerifiedActiveResponseAdmission, KernelError> {
        if stable_authorized_at_unix_ms > validation_now_unix_ms {
            return Err(active_response_denied(
                "stable active-response authorization time is in the future",
            ));
        }
        validate_executable_response_plan(request)?;
        let bindings = self.verify_active_response_authorization_at(
            request.authorization(),
            validation_now_unix_ms,
        )?;
        self.verify_active_response_artifact_authority_attestation(
            request,
            &bindings,
            validation_now_unix_ms,
        )?;
        let requirement = self.resolve_active_response_requirement(&bindings)?;
        match requirement.approval_requirement() {
            ResponseApprovalRequirement::Automatic => {
                if request.threshold_proposal().is_some() || !request.approval_tokens().is_empty() {
                    return Err(active_response_denied(
                        "automatic active response cannot carry threshold artifacts",
                    ));
                }
                let policy_decision_hash = requirement.policy_decision_hash().to_string();
                let execution = build_active_response_execution_request(
                    request,
                    requirement.executor_authority().clone(),
                    &policy_decision_hash,
                    stable_authorized_at_unix_ms,
                    ActiveResponseExecutionApproval::Automatic,
                )?;
                Ok(VerifiedActiveResponseAdmission::Automatic(
                    AutomaticActiveResponsePermit {
                        dispatch_id: execution.dispatch_id().clone(),
                        request_id: bindings.request_id().to_string(),
                        plan_body_hash: bindings.plan_body_hash().to_string(),
                        authorization_capability_hash: bindings
                            .authorization_capability_hash()
                            .to_string(),
                        governed_intent_hash: bindings.governed_intent_hash().to_string(),
                        policy_decision_hash,
                        executor_authority_id: requirement
                            .executor_authority()
                            .authority_id()
                            .to_string(),
                        executor_authority_generation: requirement
                            .executor_authority()
                            .generation(),
                        authorized_at_unix_ms: stable_authorized_at_unix_ms,
                        expires_at_unix_ms: request.response_plan().expires_at_unix_ms,
                    },
                ))
            }
            ResponseApprovalRequirement::Governed { .. } => {
                let verified_approvals = self.verify_active_response_threshold(
                    request,
                    &bindings,
                    &requirement,
                    validation_now_unix_ms / 1_000,
                )?;
                let (operation, approval_set) = build_governed_active_response_operation(
                    &bindings,
                    &requirement,
                    &verified_approvals,
                )?;
                Ok(VerifiedActiveResponseAdmission::Governed(
                    VerifiedGovernedActiveResponse {
                        operation: Box::new(operation),
                        approval_set: Box::new(approval_set),
                        policy_decision_hash: requirement.policy_decision_hash().to_string(),
                        authorized_at_unix_ms: stable_authorized_at_unix_ms,
                    },
                ))
            }
        }
    }

    fn verify_active_response_threshold(
        &self,
        request: &ActiveResponseAdmissionRequest,
        bindings: &VerifiedActiveResponseBindings,
        requirement: &VerifiedActiveResponseRequirement,
        now: u64,
    ) -> Result<VerifiedThresholdApprovalSet, KernelError> {
        let resolver = self
            .threshold_approval_requirement_resolver
            .as_deref()
            .ok_or_else(|| {
                active_response_denied("threshold approval requirement resolver is not configured")
            })?;
        let proposal = request.threshold_proposal().ok_or_else(|| {
            active_response_denied("signed threshold approval proposal is required")
        })?;
        if request.approval_tokens().is_empty() {
            return Err(active_response_denied(
                "at least one governed approval token is required",
            ));
        }
        let allowed_token_algorithms: &[SigningAlgorithm] = match self.capability_crypto_floor {
            KernelCryptoFloor::AllowClassical => &[
                SigningAlgorithm::Ed25519,
                SigningAlgorithm::P256,
                SigningAlgorithm::P384,
            ],
            KernelCryptoFloor::AllowHybrid => &[
                SigningAlgorithm::Ed25519,
                SigningAlgorithm::P256,
                SigningAlgorithm::P384,
                SigningAlgorithm::Hybrid,
            ],
            KernelCryptoFloor::PqRequired => &[SigningAlgorithm::Hybrid],
        };
        let verified = verify_threshold_approval_set(
            &ThresholdApprovalVerificationInput {
                request_id: bindings.request_id(),
                server_id: CHIO_ACTIVE_RESPONSE_SERVER_ID,
                tool_name: ACTIVE_RESPONSE_APPROVAL_TOOL_NAME,
                governed_intent_hash: bindings.governed_intent_hash(),
                subject: bindings.executor_subject(),
                authorization_capability_hash: bindings.authorization_capability_hash(),
                authorizing_capability_expires_at: bindings.operator_capability_expires_at(),
                governed_operation_expires_at: bindings.governed_operation_expires_at(),
                policy_hash: requirement.policy_hash(),
                proposal,
                approval_tokens: request.approval_tokens(),
                trusted_policy_authorities: &self.threshold_approval_policy_authorities,
                allowed_token_algorithms,
                now,
            },
            resolver,
        )
        .map_err(|error| active_response_denied(error.to_string()))?;
        if request
            .approval_tokens()
            .iter()
            .any(|token| &token.approver == bindings.authenticated_submitter())
        {
            return Err(active_response_denied(
                "response-plan submitter cannot count as an approver",
            ));
        }
        Ok(verified)
    }

    fn validate_active_response_coordinator_profiles(&self) -> Result<(), KernelError> {
        let operation_store = self.admission_operation_store.as_ref().ok_or_else(|| {
            active_response_internal("durable active-response operation store is not installed")
        })?;
        if !operation_store
            .authority_profile()
            .supports_dispatch_workers(self.dispatch_worker_count)
        {
            return Err(active_response_internal(
                "active-response operation store cannot coordinate this worker topology",
            ));
        }
        let approval_store = self.approval_store.as_ref().ok_or_else(|| {
            active_response_internal("durable active-response approval store is not installed")
        })?;
        if !approval_store
            .authority_profile()
            .supports_dispatch_workers(self.dispatch_worker_count)
        {
            return Err(active_response_internal(
                "active-response approval store cannot coordinate this worker topology",
            ));
        }
        Ok(())
    }

    fn create_active_response_operation(
        &self,
        expected: &AdmissionOperation,
    ) -> Result<AdmissionOperation, KernelError> {
        let store = self.admission_operation_store.as_ref().ok_or_else(|| {
            active_response_internal("durable active-response operation store is not installed")
        })?;
        match store.create_prepared(expected.clone()) {
            Ok(AdmissionOperationCreateOutcome::Created(operation))
            | Ok(AdmissionOperationCreateOutcome::Existing(operation))
                if operation.has_same_prepared_binding(expected) =>
            {
                Ok(operation)
            }
            Ok(_) => Err(active_response_internal(
                "active-response operation store returned a different operation",
            )),
            Err(error) => match store.load(expected.operation_id()) {
                Ok(Some(operation)) if operation.has_same_prepared_binding(expected) => {
                    Ok(operation)
                }
                _ => Err(active_response_internal(format!(
                    "active-response operation persistence failed: {error}"
                ))),
            },
        }
    }

    pub(super) fn load_active_response_operation(
        &self,
        operation_id: &str,
    ) -> Result<AdmissionOperation, KernelError> {
        self.admission_operation_store
            .as_ref()
            .ok_or_else(|| {
                active_response_internal("durable active-response operation store is not installed")
            })?
            .load(operation_id)
            .map_err(|error| {
                active_response_internal(format!(
                    "active-response operation lookup failed: {error}"
                ))
            })?
            .ok_or_else(|| active_response_internal("active-response operation is missing"))
    }

    fn reserve_active_response_approval_set(
        &self,
        operation_id: &str,
        approval_set: &ApprovalSetReservationInput,
    ) -> Result<ApprovalReservation, KernelError> {
        let store = self.approval_store.as_ref().ok_or_else(|| {
            active_response_internal("durable active-response approval store is not installed")
        })?;
        match store.reserve_approval_set(operation_id, approval_set) {
            Ok(reservation)
                if reservation.approval_set() == approval_set
                    && reservation.state() == ReplayReservationState::Reserved =>
            {
                Ok(reservation)
            }
            Ok(_) => Err(active_response_internal(
                "active-response approval store returned a different or terminal reservation",
            )),
            Err(error) => match store.get_approval_reservation(operation_id) {
                Ok(Some(reservation))
                    if reservation.approval_set() == approval_set
                        && reservation.state() == ReplayReservationState::Reserved =>
                {
                    Ok(reservation)
                }
                _ => Err(active_response_denied(format!(
                    "active-response approval reservation failed: {error}"
                ))),
            },
        }
    }

    pub(super) fn commit_active_response_approval_set(
        &self,
        operation_id: &str,
        approval_set: &ApprovalSetReservationInput,
    ) -> Result<ApprovalReservation, KernelError> {
        let store = self.approval_store.as_ref().ok_or_else(|| {
            active_response_internal("durable active-response approval store is not installed")
        })?;
        match store.commit_approval_reservation(operation_id) {
            Ok(reservation)
                if reservation.approval_set() == approval_set
                    && reservation.state() == ReplayReservationState::Committed =>
            {
                Ok(reservation)
            }
            Ok(_) => Err(active_response_internal(
                "active-response approval commit returned a different reservation",
            )),
            Err(error) => match store.get_approval_reservation(operation_id) {
                Ok(Some(reservation))
                    if reservation.approval_set() == approval_set
                        && reservation.state() == ReplayReservationState::Committed =>
                {
                    Ok(reservation)
                }
                _ => Err(active_response_internal(format!(
                    "active-response approval commit failed: {error}"
                ))),
            },
        }
    }

    fn compensate_active_response_before_dispatch(
        &self,
        reservation: &GovernedActiveResponseReservation,
        reason: &str,
    ) -> Result<(), KernelError> {
        let mut operation = self.load_active_response_operation(reservation.operation_id())?;
        if !operation.has_same_prepared_binding(&reservation.operation) {
            return Err(active_response_internal(
                "cannot compensate an active-response operation with different identity",
            ));
        }
        if operation.state() == AdmissionOperationState::DispatchCommitted {
            return Err(active_response_internal(
                "cannot compensate after active-response dispatch commitment",
            ));
        }
        if matches!(
            operation.state(),
            AdmissionOperationState::CompensationPending
                | AdmissionOperationState::CompensatedBeforeDispatch
        ) {
            if !self.recover_compensated_admission_operation(operation.operation_id())? {
                return Err(active_response_internal(
                    "active-response cleanup is owned by another recovery worker",
                ));
            }
            return Ok(());
        }
        if operation.state().is_terminal() {
            return Err(active_response_internal(
                "terminal active-response operation cannot be compensated",
            ));
        }

        let store = self.admission_operation_store.as_ref().ok_or_else(|| {
            active_response_internal("active-response admission operation store is unavailable")
        })?;
        operation = self.stage_compensation_pending_with_terminal_receipt(
            store.as_ref(),
            &operation,
            reason,
        )?;
        if operation.state() == AdmissionOperationState::CompensationPending {
            if !self.recover_compensated_admission_operation(operation.operation_id())? {
                return Err(active_response_internal(
                    "active-response cleanup is owned by another recovery worker",
                ));
            }
            return Ok(());
        }
        Err(active_response_internal(
            "active-response compensation did not enter its signed terminal outbox",
        ))
    }

    pub(super) fn active_response_cas(
        &self,
        operation: &AdmissionOperation,
        next_state: AdmissionOperationState,
        next_dispatch_state: AdmissionDispatchState,
        last_error: Option<String>,
    ) -> Result<ActiveResponseCasResult, KernelError> {
        if next_state.is_terminal() {
            return Err(active_response_internal(
                "terminal active-response transitions require an atomic signed receipt outbox",
            ));
        }
        let store = self.admission_operation_store.as_ref().ok_or_else(|| {
            active_response_internal("durable active-response operation store is not installed")
        })?;
        let expected_next = operation
            .transition_checked(
                next_state,
                next_dispatch_state,
                ACTIVE_RESPONSE_COORDINATOR_LEASE_EPOCH.max(operation.coordinator_lease_epoch()),
                last_error.clone(),
            )
            .map_err(|error| {
                active_response_internal(format!(
                    "active-response transition is invalid before persistence: {error}"
                ))
            })?;
        match store.compare_and_swap(AdmissionOperationCompareAndSwap {
            operation_id: operation.operation_id(),
            expected_version: operation.version(),
            coordinator_lease_epoch: operation.coordinator_lease_epoch(),
            next_state,
            next_dispatch_state,
            next_coordinator_lease_epoch: ACTIVE_RESPONSE_COORDINATOR_LEASE_EPOCH
                .max(operation.coordinator_lease_epoch()),
            last_error,
        }) {
            Ok(AdmissionOperationCasOutcome::Applied(next)) if next == expected_next => {
                Ok(ActiveResponseCasResult {
                    operation: next,
                    applied: true,
                })
            }
            Ok(AdmissionOperationCasOutcome::Applied(_)) => Err(active_response_internal(
                "active-response operation store returned the wrong applied transition",
            )),
            Ok(AdmissionOperationCasOutcome::Conflict(current))
                if current.has_same_prepared_binding(operation) =>
            {
                Ok(ActiveResponseCasResult {
                    operation: current,
                    applied: false,
                })
            }
            Ok(AdmissionOperationCasOutcome::Conflict(_)) => Err(active_response_internal(
                "active-response operation conflict changed immutable identity",
            )),
            Ok(AdmissionOperationCasOutcome::Missing) => Err(active_response_internal(
                "active-response operation disappeared during transition",
            )),
            Err(error) => match store.load(operation.operation_id()) {
                Ok(Some(current)) if current == expected_next => Ok(ActiveResponseCasResult {
                    operation: current,
                    applied: false,
                }),
                _ => Err(active_response_internal(format!(
                    "active-response transition acknowledgement is uncertain: {error}"
                ))),
            },
        }
    }
}

include!("active_response_coordinator/execution_validation.inc");
