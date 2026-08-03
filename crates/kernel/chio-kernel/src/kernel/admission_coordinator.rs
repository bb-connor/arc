use super::*;
use crate::approval::{ApprovalReservation, ApprovalSetReservationInput};
use crate::budget_store::{
    derive_verified_invocation_admission, BudgetAdmissionOperationBinding,
    BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest,
};
use crate::execution_nonce::{
    verify_execution_nonce_stateless, ExecutionNonceReservation, NonceBinding,
};
use crate::security_admission_operation::{
    AdmissionDispatchState, AdmissionOperation, AdmissionOperationCasOutcome,
    AdmissionOperationCompareAndSwap, AdmissionOperationCreateOutcome, AdmissionOperationState,
};
use crate::supplemental_quota::{
    OpaqueSignedSupplementalQuota, SupplementalAdmissionAuthorization, SupplementalAdmissionPlan,
    SupplementalAdmissionPrepareRequest, SupplementalQuotaDestination,
    SupplementalQuotaVerificationContext,
};
use crate::threshold_approval::PreparedGovernedToolAdmission;
use chio_core::capability::aggregate_budget::{
    verify_aggregate_invocation_authority, AggregateFamilyRootResolutionError,
};

const THRESHOLD_COORDINATOR_LEASE_EPOCH: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ThresholdPaymentMode {
    Dispatch,
    CallerReservation,
}

pub(super) struct ThresholdProtocolPreparation {
    capability_digest: String,
    arguments_digest: String,
    supplemental_artifact: Option<OpaqueSignedSupplementalQuota>,
    supplemental_plan: Option<SupplementalAdmissionPlan>,
    supplemental_digest: Option<String>,
    hold_id: String,
    authorize_event_id: String,
    reverse_event_id: String,
    capture_event_id: String,
}

#[derive(Clone, Copy)]
pub(super) struct ThresholdToolAdmissionContext<'a> {
    pub(super) request: &'a ToolCallRequest,
    pub(super) cap: &'a CapabilityToken,
    pub(super) grant_index: usize,
    pub(super) grant: &'a ToolGrant,
    pub(super) now: u64,
    pub(super) payment_mode: ThresholdPaymentMode,
}

#[derive(Clone, Copy)]
pub(super) struct ThresholdCallerReservationHandoffContext<'a> {
    pub(super) runtime_response_metadata: Option<&'a serde_json::Value>,
    pub(super) caller_receipt_metadata: Option<&'a serde_json::Value>,
}

impl ThresholdProtocolPreparation {
    pub(super) fn hold_id(&self) -> &str {
        &self.hold_id
    }

    pub(super) fn broker_attempt_id(&self) -> Option<&str> {
        self.supplemental_plan
            .as_ref()
            .map(SupplementalAdmissionPlan::attempt_id)
    }

    pub(super) fn supplemental_digest(&self) -> Option<&str> {
        self.supplemental_digest.as_deref()
    }
}

struct ThresholdBudgetAuthorization {
    request: BudgetAuthorizeHoldRequest,
    aggregate_root_capability_id: Option<String>,
    aggregate_binding_digest: Option<String>,
    supplemental_verifier_id: Option<String>,
    supplemental_request_binding_hash: Option<String>,
    supplemental_negotiated_features_digest: Option<String>,
    authorization_artifact_digests: Vec<String>,
}

struct ThresholdBudgetAuthorizationContext<'a> {
    capability: &'a CapabilityToken,
    grant_index: usize,
    grant: &'a ToolGrant,
    operation: &'a AdmissionOperation,
    protocol: &'a ThresholdProtocolPreparation,
    preexisting_operation: bool,
}

pub(super) struct ThresholdDispatchPermit {
    operation: AdmissionOperation,
    preexisting_operation: bool,
    payment_authorization: Option<PaymentAuthorization>,
    delegated_budget_lease_acquired: bool,
}

struct ThresholdPreDispatchCompensation<'a> {
    operation: &'a AdmissionOperation,
    reason: &'a str,
}

pub(super) enum ThresholdToolAdmissionFailure {
    Kernel(KernelError),
    PaymentAuthorizationOutcomeUnknown {
        failure: crate::payment::PaymentAuthorizationFailure,
        budget_mutation: PreExecutionBudgetMutation,
        delegated_budget_lease_acquired: bool,
    },
}

impl ThresholdToolAdmissionFailure {
    pub(super) fn into_kernel_error(self) -> KernelError {
        match self {
            Self::Kernel(error) => error,
            Self::PaymentAuthorizationOutcomeUnknown { failure, .. } => {
                KernelError::GovernedTransactionDenied(format!(
                    "threshold payment authorization outcome is unknown: {failure}"
                ))
            }
        }
    }
}

impl From<KernelError> for ThresholdToolAdmissionFailure {
    fn from(error: KernelError) -> Self {
        Self::Kernel(error)
    }
}

impl From<crate::security_admission_operation::AdmissionOperationError>
    for ThresholdToolAdmissionFailure
{
    fn from(error: crate::security_admission_operation::AdmissionOperationError) -> Self {
        Self::Kernel(KernelError::from(error))
    }
}

impl core::fmt::Display for ThresholdToolAdmissionFailure {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Kernel(error) => core::fmt::Display::fmt(error, formatter),
            Self::PaymentAuthorizationOutcomeUnknown { failure, .. } => write!(
                formatter,
                "threshold payment authorization outcome is unknown: {failure}"
            ),
        }
    }
}

impl core::fmt::Debug for ThresholdDispatchPermit {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ThresholdDispatchPermit")
            .field("operation_id", &self.operation.operation_id())
            .field("preexisting_operation", &self.preexisting_operation)
            .field(
                "payment_authorization_id",
                &self
                    .payment_authorization
                    .as_ref()
                    .map(|authorization| authorization.authorization_id.as_str()),
            )
            .field(
                "delegated_budget_lease_acquired",
                &self.delegated_budget_lease_acquired,
            )
            .finish_non_exhaustive()
    }
}

impl ThresholdDispatchPermit {
    pub(super) fn operation(&self) -> &AdmissionOperation {
        &self.operation
    }

    pub(super) fn preexisting_operation(&self) -> bool {
        self.preexisting_operation
    }

    pub(super) fn payment_authorization(&self) -> Option<&PaymentAuthorization> {
        self.payment_authorization.as_ref()
    }

    pub(super) fn delegated_budget_lease_acquired(&self) -> bool {
        self.delegated_budget_lease_acquired
    }

    #[cfg(test)]
    pub(super) fn operation_id(&self) -> &str {
        self.operation.operation_id()
    }
}

impl ChioKernel {
    #[cfg(test)]
    pub(super) fn coordinate_threshold_tool_admission(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        grant_index: usize,
        grant: &ToolGrant,
        prepared: PreparedGovernedToolAdmission,
    ) -> Result<(ThresholdDispatchPermit, PreExecutionBudgetMutation), KernelError> {
        let now = current_unix_timestamp();
        let protocol = self.prepare_threshold_protocol_admission(request, cap, grant_index, now)?;
        let runtime_admission = self.run_runtime_admission_hook_for_operation(
            request,
            None,
            now,
            now.saturating_mul(1_000),
            Some(grant_index),
            Some(prepared.operation()),
        );
        if !runtime_admission.allowed {
            self.release_runtime_admission_reservations(runtime_admission.metadata.as_ref())?;
            return Err(KernelError::GovernedTransactionDenied(
                runtime_admission
                    .reason
                    .unwrap_or_else(|| "runtime admission denied".to_string()),
            ));
        }
        let reserved = self.reserve_threshold_tool_admission(
            ThresholdToolAdmissionContext {
                request,
                cap,
                grant_index,
                grant,
                now,
                payment_mode: ThresholdPaymentMode::Dispatch,
            },
            prepared,
            protocol,
            None,
        );
        let (mut permit, mutation) = match reserved {
            Ok(reserved) => reserved,
            Err(error) => {
                self.release_runtime_admission_reservations(runtime_admission.metadata.as_ref())?;
                return Err(error);
            }
        };
        self.commit_reserved_threshold_protocol_dispatch(&mut permit, request, cap, &mutation)?;
        Ok((permit, mutation))
    }

    pub(super) fn prepare_threshold_protocol_admission(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        grant_index: usize,
        _now: u64,
    ) -> Result<ThresholdProtocolPreparation, KernelError> {
        self.validate_protocol_admission_runtime(cap, request)?;
        let capability_digest = crate::threshold_approval::authorization_capability_hash(cap)
            .map_err(|error| KernelError::GuardDenied(error.to_string()))?;
        let arguments_digest =
            sha256_hex(&canonical_json_bytes(&request.arguments).map_err(|error| {
                KernelError::GuardDenied(format!(
                    "tool arguments failed canonical admission binding: {error}"
                ))
            })?);
        let supplemental_artifact = request
            .supplemental_quota_authorization()
            .map(|authorization| {
                OpaqueSignedSupplementalQuota::new(authorization.artifact().to_vec())
                    .map_err(|error| KernelError::GuardDenied(error.to_string()))
            })
            .transpose()?;
        let supplemental_plan = match (
            request.supplemental_quota_authorization(),
            supplemental_artifact.as_ref(),
        ) {
            (Some(authorization), Some(artifact)) => {
                let registrar =
                    self.supplemental_admission_registrar
                        .as_ref()
                        .ok_or_else(|| {
                            KernelError::GuardDenied(
                                "supplemental admission registrar is unavailable".to_string(),
                            )
                        })?;
                Some(
                    registrar
                        .prepare_admission(SupplementalAdmissionPrepareRequest {
                            request_id: &request.request_id,
                            capability_id: &cap.id,
                            arguments: &request.arguments,
                            authorization_reference: authorization.reference(),
                            authorization_artifact: artifact,
                        })
                        .map_err(|error| KernelError::GuardDenied(error.to_string()))?,
                )
            }
            (None, None) => None,
            _ => {
                return Err(KernelError::Internal(
                    "supplemental authorization preparation diverged".to_string(),
                ));
            }
        };
        let hold_id = supplemental_plan.as_ref().map_or_else(
            || {
                format!(
                    "budget-hold:{}:{}:{}",
                    request.request_id, cap.id, grant_index
                )
            },
            |plan| plan.hold_id().to_string(),
        );
        let authorize_event_id = supplemental_plan.as_ref().map_or_else(
            || format!("{hold_id}:authorize"),
            |plan| plan.authorize_event_id().to_string(),
        );
        let reverse_event_id = supplemental_plan.as_ref().map_or_else(
            || format!("{hold_id}:reverse"),
            |plan| plan.reverse_event_id().to_string(),
        );
        let capture_event_id = supplemental_plan.as_ref().map_or_else(
            || format!("{hold_id}:capture-invocations"),
            |plan| plan.capture_event_id().to_string(),
        );
        let supplemental_digest = supplemental_artifact
            .as_ref()
            .map(OpaqueSignedSupplementalQuota::digest)
            .or_else(|| request.credit_facility_bind_artifact().map(sha256_hex));
        Ok(ThresholdProtocolPreparation {
            capability_digest,
            arguments_digest,
            supplemental_artifact,
            supplemental_plan,
            supplemental_digest,
            hold_id,
            authorize_event_id,
            reverse_event_id,
            capture_event_id,
        })
    }

    #[cfg(test)]
    pub(super) fn reserve_threshold_tool_admission(
        &self,
        context: ThresholdToolAdmissionContext<'_>,
        prepared: PreparedGovernedToolAdmission,
        protocol: ThresholdProtocolPreparation,
        caller_handoff: Option<ThresholdCallerReservationHandoffContext<'_>>,
    ) -> Result<(ThresholdDispatchPermit, PreExecutionBudgetMutation), KernelError> {
        self.reserve_threshold_tool_admission_with_payee_binding(
            context,
            prepared,
            protocol,
            caller_handoff,
            None,
        )
        .map_err(ThresholdToolAdmissionFailure::into_kernel_error)
    }

    pub(super) fn reserve_threshold_tool_admission_with_payee_binding(
        &self,
        context: ThresholdToolAdmissionContext<'_>,
        prepared: PreparedGovernedToolAdmission,
        protocol: ThresholdProtocolPreparation,
        caller_handoff: Option<ThresholdCallerReservationHandoffContext<'_>>,
        verified_payee_binding: Option<&VerifiedGovernedPayeeBinding>,
    ) -> Result<(ThresholdDispatchPermit, PreExecutionBudgetMutation), ThresholdToolAdmissionFailure>
    {
        if (context.payment_mode == ThresholdPaymentMode::CallerReservation)
            != caller_handoff.is_some()
        {
            return Err(KernelError::Internal(
                "threshold caller-reservation handoff context does not match payment mode"
                    .to_string(),
            )
            .into());
        }
        self.validate_protocol_budget_admission_profiles()?;
        self.validate_threshold_coordinator_profiles(context.request.execution_nonce.is_some())?;
        self.verify_threshold_execution_nonce_stateless(
            context.request,
            context.cap,
            context.payment_mode,
        )?;

        if prepared.operation().budget_hold_id() != Some(protocol.hold_id.as_str())
            || prepared.operation().broker_attempt_id() != protocol.broker_attempt_id()
        {
            return Err(KernelError::GovernedTransactionDenied(
                "threshold admission participant bindings do not match prepared protocol authority"
                    .to_string(),
            )
            .into());
        }
        let ThresholdToolAdmissionContext {
            request,
            cap,
            grant_index,
            grant,
            now,
            payment_mode,
        } = context;

        let (prepared_operation, approval_set) = prepared.into_parts();
        let operation_store = self.admission_operation_store.as_ref().ok_or_else(|| {
            KernelError::Internal("durable admission operation store is not installed".to_string())
        })?;
        let (mut operation, preexisting_operation) = match operation_store
            .create_prepared(prepared_operation)
            .map_err(KernelError::from)?
        {
            AdmissionOperationCreateOutcome::Created(operation) => (operation, false),
            AdmissionOperationCreateOutcome::Existing(operation) => (operation, true),
        };
        let authorization = if preexisting_operation {
            self.frozen_threshold_budget_authorization(
                operation_store.as_ref(),
                &operation,
                cap,
                grant_index,
                &protocol,
            )?
        } else {
            self.prepare_threshold_budget_authorization(
                &ThresholdToolAdmissionContext {
                    request,
                    cap,
                    grant_index,
                    grant,
                    now,
                    payment_mode,
                },
                &operation,
                &protocol,
                verified_payee_binding
                    .is_some_and(VerifiedGovernedPayeeBinding::is_credit_facility),
            )?
        };
        self.journal_budget_cleanup(
            &operation,
            &authorization.request,
            protocol.reverse_event_id.clone(),
            protocol.capture_event_id.clone(),
        )?;
        if let Some(attempt_id) = operation.broker_attempt_id() {
            self.journal_broker_cleanup(&operation, attempt_id.to_string())?;
        }
        if let Some(parent) = cap.delegation_chain.last() {
            self.journal_delegated_budget_cleanup(
                &operation,
                parent.capability_id.clone(),
                cap.id.clone(),
                cap.budget_share_bps
                    .unwrap_or(chio_kernel_core::MAX_BUDGET_SHARE_BPS),
            )?;
        }
        if self.payment_adapter.is_some()
            && verified_payee_binding.is_none_or(|binding| !binding.is_credit_facility())
            && (payment_mode == ThresholdPaymentMode::Dispatch
                || Self::is_governed_mustprepay_request(request))
        {
            let payment_terms = Self::mustprepay_quoted_amount(request)
                .or_else(|| self.ordinary_payment_charge_terms(grant));
            if let Some((amount_units, currency)) = payment_terms {
                self.journal_payment_cleanup(
                    &operation,
                    amount_units,
                    currency,
                    request.request_id.clone(),
                )?;
            }
        }
        if operation.approval_set_hash().is_some() {
            self.journal_approval_cleanup(&operation, &approval_set)?;
        }
        if let Some(nonce_id) = operation.execution_nonce_id() {
            self.journal_nonce_cleanup(&operation, nonce_id.to_string())?;
        }
        if matches!(
            operation.state(),
            AdmissionOperationState::CompensationPending
                | AdmissionOperationState::CompensatedBeforeDispatch
        ) {
            if !self.recover_compensated_admission_operation(operation.operation_id())? {
                return Err(KernelError::Internal(format!(
                    "threshold admission operation {} has cleanup owned by another worker",
                    operation.operation_id()
                ))
                .into());
            }
            operation = operation_store
                .load(operation.operation_id())?
                .ok_or_else(|| {
                    KernelError::Internal(
                        "threshold admission disappeared after compensation recovery".to_string(),
                    )
                })?;
        }
        if operation.state().is_terminal()
            || operation.state() == AdmissionOperationState::DispatchCommitted
        {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "threshold admission operation {} is already {}",
                operation.operation_id(),
                operation.state().as_str()
            ))
            .into());
        }

        if operation.state() == AdmissionOperationState::Prepared {
            if let Some(plan) = protocol.supplemental_plan.as_ref() {
                let registrar =
                    self.supplemental_admission_registrar
                        .as_ref()
                        .ok_or_else(|| {
                            KernelError::Internal(
                                "supplemental admission registrar disappeared".to_string(),
                            )
                        })?;
                if let Err(error) = registrar.register_admission(
                    plan,
                    SupplementalAdmissionAuthorization::new(
                        operation.operation_id(),
                        &authorization.request,
                    ),
                ) {
                    let terminal = self.claim_pre_dispatch_compensation(
                        operation.operation_id(),
                        &error.to_string(),
                    )?;
                    if terminal.is_none() {
                        return Err(KernelError::Internal(
                            "threshold broker registration failure lost the compensation-dispatch race"
                                .to_string(),
                        )
                        .into());
                    }
                    let _ = registrar.release_admission(operation.operation_id());
                    return Err(KernelError::GuardDenied(error.to_string()).into());
                }
                operation = self.threshold_cas_recover(
                    &operation,
                    AdmissionOperationState::BrokerAttemptRegistered,
                    AdmissionDispatchState::NotStarted,
                    None,
                )?;
            }
        }

        let budget_context = ThresholdBudgetAuthorizationContext {
            capability: cap,
            grant_index,
            grant,
            operation: &operation,
            protocol: &protocol,
            preexisting_operation,
        };
        let budget_mutation = match self.authorize_threshold_budget(budget_context, authorization) {
            Ok(mutation) => mutation,
            Err(error @ KernelError::BudgetExhausted(_))
                if matches!(
                    operation.state(),
                    AdmissionOperationState::Prepared
                        | AdmissionOperationState::BrokerAttemptRegistered
                ) =>
            {
                let terminal = self.claim_pre_dispatch_compensation(
                    operation.operation_id(),
                    &error.to_string(),
                )?;
                if terminal.is_none() {
                    return Err(KernelError::Internal(
                        "threshold budget denial raced with an admission transition".to_string(),
                    )
                    .into());
                }
                if let Some(registrar) = self.supplemental_admission_registrar.as_ref() {
                    let _ = registrar.release_admission(operation.operation_id());
                }
                return Err(error.into());
            }
            Err(error)
                if matches!(
                    operation.state(),
                    AdmissionOperationState::Prepared
                        | AdmissionOperationState::BrokerAttemptRegistered
                ) =>
            {
                let terminal = self.claim_pre_dispatch_compensation(
                    operation.operation_id(),
                    &error.to_string(),
                )?;
                if terminal.is_none() {
                    return Err(KernelError::Internal(
                        "threshold budget failure lost the compensation-dispatch race".to_string(),
                    )
                    .into());
                }
                return Err(error.into());
            }
            Err(error) => return Err(error.into()),
        };

        if matches!(
            operation.state(),
            AdmissionOperationState::Prepared | AdmissionOperationState::BrokerAttemptRegistered
        ) {
            operation = self.threshold_cas_recover(
                &operation,
                AdmissionOperationState::BudgetAuthorized,
                AdmissionDispatchState::NotStarted,
                None,
            )?;
        }

        if let Some(handoff) = caller_handoff {
            let admission = budget_mutation.ordinary_admission().ok_or_else(|| {
                KernelError::Internal(
                    "threshold caller reservation omitted operation-owned admission mutation"
                        .to_string(),
                )
            })?;
            let response_metadata = self.caller_reservation_response_metadata(
                &budget_mutation,
                handoff.runtime_response_metadata.cloned(),
            )?;
            if let Err(error) = self.prepare_operation_owned_caller_reservation_handoff(
                request,
                now,
                grant_index,
                admission,
                response_metadata,
                handoff.caller_receipt_metadata,
            ) {
                if operation.state() == AdmissionOperationState::BudgetAuthorized {
                    self.compensate_threshold_before_dispatch(ThresholdPreDispatchCompensation {
                        operation: &operation,
                        reason: &error.to_string(),
                    })?;
                }
                return Err(error.into());
            }
        }

        let mut delegated_budget_lease_acquired = false;
        let mut payment_authorization = None;
        loop {
            if matches!(
                operation.state(),
                AdmissionOperationState::DelegatedBudgetReserved
                    | AdmissionOperationState::PaymentAuthorized
                    | AdmissionOperationState::ApprovalReserved
                    | AdmissionOperationState::ReadyToDispatch
                    | AdmissionOperationState::CapturePending
                    | AdmissionOperationState::CallerReservationCapturePending
            ) {
                match self.reserve_threshold_delegated_budget(cap, &operation) {
                    Ok(acquired) => delegated_budget_lease_acquired = acquired,
                    Err(error) => {
                        if !matches!(
                            operation.state(),
                            AdmissionOperationState::CapturePending
                                | AdmissionOperationState::CallerReservationCapturePending
                        ) {
                            self.compensate_threshold_before_dispatch(
                                ThresholdPreDispatchCompensation {
                                    operation: &operation,
                                    reason: &error.to_string(),
                                },
                            )?;
                        }
                        return Err(error.into());
                    }
                }
            }
            if matches!(
                operation.state(),
                AdmissionOperationState::PaymentAuthorized
                    | AdmissionOperationState::ApprovalReserved
                    | AdmissionOperationState::ReadyToDispatch
                    | AdmissionOperationState::CapturePending
                    | AdmissionOperationState::CallerReservationCapturePending
            ) && payment_authorization.is_none()
            {
                match self.authorize_threshold_payment_with_recovery(
                    request,
                    &budget_mutation,
                    payment_mode,
                    verified_payee_binding,
                ) {
                    Ok(authorization) => payment_authorization = authorization,
                    Err(error) => {
                        if error.outcome_unknown_reason().is_some() {
                            return Err(
                                ThresholdToolAdmissionFailure::PaymentAuthorizationOutcomeUnknown {
                                    failure: error,
                                    budget_mutation,
                                    delegated_budget_lease_acquired,
                                },
                            );
                        }
                        if !matches!(
                            operation.state(),
                            AdmissionOperationState::CapturePending
                                | AdmissionOperationState::CallerReservationCapturePending
                        ) {
                            self.compensate_threshold_before_dispatch(
                                ThresholdPreDispatchCompensation {
                                    operation: &operation,
                                    reason: &error.to_string(),
                                },
                            )?;
                        }
                        return Err(KernelError::GovernedTransactionDenied(format!(
                            "threshold payment authorization failed: {error}"
                        ))
                        .into());
                    }
                }
            }

            operation = match operation.state() {
                AdmissionOperationState::BudgetAuthorized => {
                    match self.reserve_threshold_delegated_budget(cap, &operation) {
                        Ok(acquired) => delegated_budget_lease_acquired = acquired,
                        Err(error) => {
                            self.compensate_threshold_before_dispatch(
                                ThresholdPreDispatchCompensation {
                                    operation: &operation,
                                    reason: &error.to_string(),
                                },
                            )?;
                            return Err(error.into());
                        }
                    }
                    self.threshold_cas_recover(
                        &operation,
                        AdmissionOperationState::DelegatedBudgetReserved,
                        AdmissionDispatchState::NotStarted,
                        None,
                    )?
                }
                AdmissionOperationState::DelegatedBudgetReserved => {
                    payment_authorization = match self.authorize_threshold_payment_with_recovery(
                        request,
                        &budget_mutation,
                        payment_mode,
                        verified_payee_binding,
                    ) {
                        Ok(authorization) => authorization,
                        Err(error) => {
                            if error.outcome_unknown_reason().is_some() {
                                return Err(
                                    ThresholdToolAdmissionFailure::PaymentAuthorizationOutcomeUnknown {
                                        failure: error,
                                        budget_mutation,
                                        delegated_budget_lease_acquired,
                                    },
                                );
                            }
                            self.compensate_threshold_before_dispatch(
                                ThresholdPreDispatchCompensation {
                                    operation: &operation,
                                    reason: &error.to_string(),
                                },
                            )?;
                            return Err(KernelError::GovernedTransactionDenied(format!(
                                "threshold payment authorization failed: {error}"
                            ))
                            .into());
                        }
                    };
                    self.threshold_cas_recover(
                        &operation,
                        AdmissionOperationState::PaymentAuthorized,
                        AdmissionDispatchState::NotStarted,
                        None,
                    )?
                }
                AdmissionOperationState::PaymentAuthorized => {
                    if let Err(error) =
                        self.reserve_threshold_approval_set(operation.operation_id(), &approval_set)
                    {
                        self.compensate_threshold_before_dispatch(
                            ThresholdPreDispatchCompensation {
                                operation: &operation,
                                reason: &error.to_string(),
                            },
                        )?;
                        return Err(error.into());
                    }
                    self.threshold_cas_recover(
                        &operation,
                        AdmissionOperationState::ApprovalReserved,
                        AdmissionDispatchState::NotStarted,
                        None,
                    )?
                }
                AdmissionOperationState::ApprovalReserved => {
                    if let Err(error) = self.reserve_threshold_execution_nonce(&operation, request)
                    {
                        self.compensate_threshold_before_dispatch(
                            ThresholdPreDispatchCompensation {
                                operation: &operation,
                                reason: &error.to_string(),
                            },
                        )?;
                        return Err(error.into());
                    }
                    self.threshold_cas_recover(
                        &operation,
                        AdmissionOperationState::ReadyToDispatch,
                        AdmissionDispatchState::NotStarted,
                        None,
                    )?
                }
                AdmissionOperationState::ReadyToDispatch => {
                    if operation.broker_attempt_id().is_some() {
                        let preparation = self
                            .supplemental_admission_registrar
                            .as_ref()
                            .ok_or_else(|| {
                                KernelError::Internal(
                                    "supplemental admission registrar disappeared before threshold dispatch"
                                        .to_string(),
                                )
                            })?
                            .prepare_dispatch(operation.operation_id());
                        if let Err(error) = preparation {
                            self.compensate_threshold_before_dispatch(
                                ThresholdPreDispatchCompensation {
                                    operation: &operation,
                                    reason: &error.to_string(),
                                },
                            )?;
                            return Err(KernelError::GuardDenied(error.to_string()).into());
                        }
                    }
                    return Ok((
                        ThresholdDispatchPermit {
                            operation,
                            preexisting_operation,
                            payment_authorization,
                            delegated_budget_lease_acquired,
                        },
                        budget_mutation,
                    ));
                }
                AdmissionOperationState::CapturePending
                | AdmissionOperationState::CallerReservationCapturePending => {
                    return Ok((
                        ThresholdDispatchPermit {
                            operation,
                            preexisting_operation,
                            payment_authorization,
                            delegated_budget_lease_acquired,
                        },
                        budget_mutation,
                    ));
                }
                AdmissionOperationState::DispatchCommitted
                | AdmissionOperationState::CallerReserved
                | AdmissionOperationState::Completed
                | AdmissionOperationState::CompensationPending
                | AdmissionOperationState::CompensatedBeforeDispatch
                | AdmissionOperationState::OutcomeUnknownAfterDispatch => {
                    return Err(KernelError::GovernedTransactionDenied(format!(
                        "threshold admission operation {} cannot dispatch from {}",
                        operation.operation_id(),
                        operation.state().as_str()
                    ))
                    .into());
                }
                AdmissionOperationState::Prepared
                | AdmissionOperationState::BrokerAttemptRegistered => {
                    return Err(KernelError::Internal(
                        "threshold admission did not persist budget authorization".to_string(),
                    )
                    .into());
                }
            };
        }
    }

    pub(super) fn commit_reserved_threshold_protocol_dispatch(
        &self,
        permit: &mut ThresholdDispatchPermit,
        _request: &ToolCallRequest,
        cap: &CapabilityToken,
        mutation: &PreExecutionBudgetMutation,
    ) -> Result<serde_json::Value, KernelError> {
        let mut operation = self
            .admission_operation_store
            .as_ref()
            .ok_or_else(|| {
                KernelError::Internal(
                    "durable admission operation store is not installed".to_string(),
                )
            })?
            .load(permit.operation.operation_id())?
            .ok_or_else(|| {
                KernelError::Internal(
                    "threshold admission operation disappeared before capture".to_string(),
                )
            })?;
        if operation.state() == AdmissionOperationState::ReadyToDispatch {
            operation = self.threshold_cas_recover(
                &operation,
                AdmissionOperationState::CapturePending,
                AdmissionDispatchState::NotStarted,
                None,
            )?;
        }
        if operation.state() != AdmissionOperationState::CapturePending {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "threshold admission operation {} cannot capture from {}",
                operation.operation_id(),
                operation.state().as_str()
            )));
        }
        permit.operation = operation.clone();
        let admission = mutation.ordinary_admission().ok_or_else(|| {
            KernelError::Internal(
                "threshold admission omitted its composite budget mutation".to_string(),
            )
        })?;
        if let Err(error) = self.commit_threshold_approval(operation.operation_id()) {
            self.compensate_capture_pending_threshold_before_dispatch(
                permit,
                cap,
                admission,
                &error.to_string(),
            )?;
            return Err(error);
        }
        self.discharge_admission_cleanup_action(
            &operation,
            crate::security_admission_operation::AdmissionCleanupActionKind::Approval,
        )?;
        if let Err(error) = self.commit_admission_execution_nonce(&operation) {
            self.compensate_capture_pending_threshold_before_dispatch(
                permit,
                cap,
                admission,
                &error.to_string(),
            )?;
            return Err(error);
        }
        if operation.execution_nonce_id().is_some() {
            self.discharge_admission_cleanup_action(
                &operation,
                crate::security_admission_operation::AdmissionCleanupActionKind::ExecutionNonce,
            )?;
        }
        let metadata = match self.commit_threshold_protocol_dispatch(cap, admission) {
            Ok(metadata) => metadata,
            Err(error @ KernelError::CapabilityRevoked(_)) => {
                let compensated = self
                    .admission_operation_store
                    .as_ref()
                    .ok_or_else(|| {
                        KernelError::Internal(
                            "durable admission operation store is not installed".to_string(),
                        )
                    })?
                    .load(operation.operation_id())?
                    .ok_or_else(|| {
                        KernelError::Internal(
                            "threshold admission operation disappeared after capture denial"
                                .to_string(),
                        )
                    })?;
                if compensated.state() != AdmissionOperationState::CompensatedBeforeDispatch {
                    return Err(KernelError::Internal(
                        "capture denial did not persist threshold compensation".to_string(),
                    ));
                }
                // Publish the durable compensation winner to the caller. The
                // compensation journal has already released every participant
                // exactly once before terminalizing this operation.
                permit.operation = compensated.clone();
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        // Replay tombstones are committed before the capture authority is
        // entered. A definitive capture denial reverses the budget hold while
        // leaving those tombstones consumed. Once capture succeeds,
        // CapturePending is an uncertainty boundary and must never compensate
        // the captured quota.
        let committed = self.commit_tool_dispatch_once(&operation)?.ok_or_else(|| {
            KernelError::GovernedTransactionDenied(format!(
                "threshold admission operation {} was committed by another coordinator",
                operation.operation_id()
            ))
        })?;
        permit.operation = committed.clone();
        self.bind_threshold_dispatch_receipt_operation(admission, &committed, &metadata)
    }

    fn compensate_capture_pending_threshold_before_dispatch(
        &self,
        permit: &mut ThresholdDispatchPermit,
        cap: &CapabilityToken,
        admission: &OrdinaryAdmissionMutation,
        reason: &str,
    ) -> Result<(), KernelError> {
        let reversed =
            self.reverse_ordinary_protocol_admission_from_capture_pending(cap, admission, reason);
        let operation = self
            .admission_operation_store
            .as_ref()
            .ok_or_else(|| {
                KernelError::Internal(
                    "durable admission operation store is not installed".to_string(),
                )
            })?
            .load(permit.operation.operation_id())?
            .ok_or_else(|| {
                KernelError::Internal(
                    "threshold admission operation disappeared during replay-commit compensation"
                        .to_string(),
                )
            })?;
        if operation.state() != AdmissionOperationState::CompensatedBeforeDispatch {
            return Err(KernelError::Internal(
                "replay-commit failure did not persist signed threshold compensation".to_string(),
            ));
        }
        self.validate_terminal_receipt_binding_with_store(
            self.admission_operation_store
                .as_ref()
                .ok_or_else(|| {
                    KernelError::Internal(
                        "durable admission operation store is not installed".to_string(),
                    )
                })?
                .as_ref(),
            &operation,
        )?;
        permit.operation = operation;
        reversed.map(|_| ())
    }

    pub(super) fn exact_compensated_threshold_admission_metadata(
        &self,
        prepared: &AdmissionOperation,
    ) -> Result<Option<serde_json::Value>, KernelError> {
        let Some(store) = self.admission_operation_store.as_ref() else {
            return Ok(None);
        };
        let Some(operation) = store.load(prepared.operation_id())? else {
            return Ok(None);
        };
        if !operation.has_same_prepared_binding(prepared) {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "governed admission operation {} was rebound during failed reservation recovery",
                prepared.operation_id()
            )));
        }
        if !matches!(
            operation.state(),
            AdmissionOperationState::CompensationPending
                | AdmissionOperationState::CompensatedBeforeDispatch
        ) {
            return Ok(None);
        }
        if operation.dispatch_state() != AdmissionDispatchState::NotStarted
            || operation.last_error().is_none()
        {
            return Err(KernelError::Internal(format!(
                "compensated governed admission operation {} omitted exact non-dispatch failure metadata",
                operation.operation_id()
            )));
        }
        Ok(Some(self.ordinary_admission_operation_metadata(&operation)))
    }

    pub(super) fn refresh_threshold_dispatch_permit_metadata(
        &self,
        permit: &mut ThresholdDispatchPermit,
    ) -> Result<serde_json::Value, KernelError> {
        let store = self.admission_operation_store.as_ref().ok_or_else(|| {
            KernelError::Internal("durable admission operation store is unavailable".to_string())
        })?;
        let operation = store
            .load(permit.operation.operation_id())?
            .ok_or_else(|| {
                KernelError::Internal(format!(
                    "governed admission operation {} disappeared before receipt projection",
                    permit.operation.operation_id()
                ))
            })?;
        if !operation.has_same_prepared_binding(&permit.operation) {
            return Err(KernelError::GovernedTransactionDenied(format!(
                "governed admission operation {} was rebound before receipt projection",
                permit.operation.operation_id()
            )));
        }
        permit.operation = operation;
        Ok(self.ordinary_admission_operation_metadata(&permit.operation))
    }

    fn validate_threshold_coordinator_profiles(
        &self,
        nonce_present: bool,
    ) -> Result<(), KernelError> {
        let operation_store = self.admission_operation_store.as_ref().ok_or_else(|| {
            KernelError::Internal("durable admission operation store is required".to_string())
        })?;
        if !operation_store
            .authority_profile()
            .supports_dispatch_workers(self.dispatch_worker_count)
        {
            return Err(KernelError::Internal(
                "admission operation store cannot coordinate this worker topology".to_string(),
            ));
        }
        let approval_store = self.approval_store.as_ref().ok_or_else(|| {
            KernelError::Internal("durable approval store is required".to_string())
        })?;
        if !approval_store
            .authority_profile()
            .supports_dispatch_workers(self.dispatch_worker_count)
        {
            return Err(KernelError::Internal(
                "approval store cannot coordinate this worker topology".to_string(),
            ));
        }
        if !self
            .budget_store
            .authority_profile()
            .supports_dispatch_workers(self.dispatch_worker_count)
        {
            return Err(KernelError::Internal(
                "durable budget store cannot coordinate this worker topology".to_string(),
            ));
        }
        if nonce_present {
            let nonce_store = self.execution_nonce_store.as_deref().ok_or_else(|| {
                KernelError::Internal("durable execution nonce store is required".to_string())
            })?;
            if !nonce_store
                .authority_profile()
                .supports_dispatch_workers(self.dispatch_worker_count)
            {
                return Err(KernelError::Internal(
                    "execution nonce store cannot coordinate this worker topology".to_string(),
                ));
            }
        }
        Ok(())
    }

    fn verify_threshold_execution_nonce_stateless(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        payment_mode: ThresholdPaymentMode,
    ) -> Result<(), KernelError> {
        let Some(presented) = request.execution_nonce.as_ref() else {
            if self.execution_nonce_required() && payment_mode == ThresholdPaymentMode::Dispatch {
                return Err(KernelError::Internal(
                    "execution nonce required but not presented on threshold tool call".to_string(),
                ));
            }
            return Ok(());
        };
        let parameter_hash = ToolCallAction::from_parameters(request.arguments.clone())
            .map_err(|error| {
                KernelError::ReceiptSigningFailed(format!(
                    "failed to hash threshold tool parameters: {error}"
                ))
            })?
            .parameter_hash;
        let expected = NonceBinding {
            subject_id: cap.subject.to_hex(),
            request_id: request.request_id.clone(),
            capability_id: cap.id.clone(),
            tool_server: request.server_id.clone(),
            tool_name: request.tool_name.clone(),
            parameter_hash,
        };
        let now = i64::try_from(current_unix_timestamp()).unwrap_or(i64::MAX);
        let claimed_issuer = self.public_key();
        verify_execution_nonce_stateless(presented, &claimed_issuer, &expected, now)
            .map_err(KernelError::from)?;
        self.verify_execution_nonce_artifact_trust(presented, &claimed_issuer)
            .map_err(KernelError::from)
    }

    fn frozen_threshold_budget_authorization(
        &self,
        operation_store: &dyn crate::security_admission_operation::AdmissionOperationStore,
        operation: &AdmissionOperation,
        cap: &CapabilityToken,
        grant_index: usize,
        protocol: &ThresholdProtocolPreparation,
    ) -> Result<ThresholdBudgetAuthorization, KernelError> {
        let snapshot = self.load_recovery_budget_snapshot(operation_store, operation)?;
        if snapshot.hold_id() != protocol.hold_id.as_str()
            || snapshot.reverse_event_id() != protocol.reverse_event_id.as_str()
            || snapshot.capture_event_id() != protocol.capture_event_id.as_str()
            || snapshot.request_binding_hash() != operation.request_binding_hash()
        {
            return Err(KernelError::GovernedTransactionDenied(
                "existing threshold admission changed its frozen budget participant binding"
                    .to_string(),
            ));
        }
        let request = snapshot.authorization_request()?;
        if request.capability_id != cap.id
            || request.grant_index != grant_index
            || request.hold_id.as_deref() != Some(protocol.hold_id.as_str())
            || request.event_id.as_deref() != Some(protocol.authorize_event_id.as_str())
        {
            return Err(KernelError::GovernedTransactionDenied(
                "existing threshold admission changed its frozen budget authorization".to_string(),
            ));
        }
        let evidence = request.invocation_admission_evidence().ok_or_else(|| {
            KernelError::Internal(
                "existing threshold authorization omitted frozen admission evidence".to_string(),
            )
        })?;
        Ok(ThresholdBudgetAuthorization {
            aggregate_root_capability_id: evidence
                .aggregate_root_capability_id()
                .map(str::to_string),
            aggregate_binding_digest: evidence.aggregate_binding_digest().map(str::to_string),
            supplemental_verifier_id: evidence.supplemental_verifier_id().map(str::to_string),
            supplemental_request_binding_hash: evidence
                .supplemental_request_binding_hash()
                .map(str::to_string),
            supplemental_negotiated_features_digest: evidence
                .supplemental_negotiated_features_digest()
                .map(str::to_string),
            authorization_artifact_digests: snapshot.authorization_artifact_digests(),
            request,
        })
    }

    fn prepare_threshold_budget_authorization(
        &self,
        context: &ThresholdToolAdmissionContext<'_>,
        operation: &AdmissionOperation,
        protocol: &ThresholdProtocolPreparation,
        credit_facility: bool,
    ) -> Result<ThresholdBudgetAuthorization, KernelError> {
        let ThresholdToolAdmissionContext {
            request,
            cap,
            grant_index,
            grant,
            now,
            payment_mode,
        } = *context;
        let negotiation = self
            .capability_negotiation_for_remote(request.federated_origin_kernel_id.as_deref(), now)
            .map_err(KernelError::GuardDenied)?;
        let trusted = self
            .trusted_issuer_keys_for(cap, now)
            .map_err(KernelError::GuardDenied)?;
        let missing_root = |_root_id: &str| Err(AggregateFamilyRootResolutionError::Missing);
        let resolver: &dyn chio_core::capability::aggregate_budget::AggregateFamilyRootResolver =
            match self.aggregate_family_root_resolver.as_deref() {
                Some(resolver) => resolver,
                None => &missing_root,
            };
        let aggregate = verify_aggregate_invocation_authority(cap, &trusted, &trusted, resolver)
            .map_err(|error| {
                KernelError::GuardDenied(format!(
                    "aggregate invocation authority verification failed: {error}"
                ))
            })?;
        let supplemental = match protocol.supplemental_artifact.as_ref() {
            Some(artifact) => Some(
                self.verify_supplemental_quota(
                    artifact,
                    &SupplementalQuotaVerificationContext {
                        capability_id: cap.id.clone(),
                        capability_digest: protocol.capability_digest.clone(),
                        subject: cap.subject.clone(),
                        request_id: request.request_id.clone(),
                        destination: SupplementalQuotaDestination::new(
                            request.server_id.clone(),
                            request.tool_name.clone(),
                        )
                        .map_err(|error| KernelError::GuardDenied(error.to_string()))?,
                        arguments_digest: protocol.arguments_digest.clone(),
                        request_binding_hash: operation.request_binding_hash().to_string(),
                        now,
                        negotiated_profile:
                            crate::budget_store::BudgetQuotaProfile::SupplementalBrokerExecution,
                        negotiated_features: negotiation,
                    },
                )
                .map_err(|error| KernelError::GuardDenied(error.to_string()))?,
            ),
            None => None,
        };
        let verified_ancestor_ids: Vec<String> = cap
            .delegation_chain
            .iter()
            .map(|link| link.capability_id.clone())
            .collect();
        let invocation_admission = derive_verified_invocation_admission(
            &cap.id,
            grant_index,
            grant.max_invocations,
            aggregate.as_ref(),
            supplemental.as_ref(),
            &verified_ancestor_ids,
        )?;
        let invocation_admission = match self.partition_escrow_registry.as_ref() {
            Some(registry) => registry
                .install_verified_admission(
                    cap,
                    grant_index,
                    aggregate.as_ref(),
                    supplemental.as_ref(),
                    invocation_admission,
                    now,
                )
                .map_err(|error| {
                    KernelError::GuardDenied(format!(
                        "partition escrow admission verification failed: {error}"
                    ))
                })?,
            None => invocation_admission,
        };
        let cost_units = grant
            .max_cost_per_invocation
            .as_ref()
            .map_or(0, |amount| amount.units);
        let max_per = grant
            .max_cost_per_invocation
            .as_ref()
            .map(|amount| amount.units);
        let max_total = grant.max_total_cost.as_ref().map(|amount| amount.units);
        let mut authorization = BudgetAuthorizeHoldRequest::legacy(
            cap.id.clone(),
            grant_index,
            None,
            cost_units,
            max_per,
            max_total,
            Some(protocol.hold_id.clone()),
            Some(protocol.authorize_event_id.clone()),
            Some(self.budget_event_authority()),
        );
        authorization.admission_operation = Some(BudgetAdmissionOperationBinding::new(
            operation.operation_id().to_string(),
            operation.request_binding_hash().to_string(),
        )?);
        if self.payment_journal_active()
            && !credit_facility
            && (payment_mode == ThresholdPaymentMode::Dispatch
                || Self::is_governed_mustprepay_request(request))
        {
            let payment_terms = Self::mustprepay_quoted_amount(request)
                .or_else(|| self.ordinary_payment_charge_terms(grant));
            if let Some((amount_units, currency)) = payment_terms {
                let created_at_unix_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|elapsed| elapsed.as_millis().min(u64::MAX as u128) as u64)
                    .unwrap_or(0);
                let rail = self
                    .payment_adapter
                    .as_ref()
                    .map(|adapter| adapter.rail_id().to_string())
                    .unwrap_or_default();
                let tenant_id = self
                    .receipt_tenant_id_for_request(Some(&request.request_id))
                    .unwrap_or_else(current_scoped_receipt_tenant_id);
                authorization.payment_journal = Some(crate::payment::PaymentJournalRecord {
                    request_id: request.request_id.clone(),
                    capability_id: cap.id.clone(),
                    grant_index: grant_index as u32,
                    admission_operation: authorization.admission_operation.clone(),
                    authority: authorization.authority.clone(),
                    hold_id: Some(protocol.hold_id.clone()),
                    rail,
                    authorization_id: None,
                    transaction_id: None,
                    amount_units,
                    budget_exposure_units: cost_units,
                    settle_action: None,
                    settle_amount_units: None,
                    currency,
                    state: crate::payment::PaymentJournalState::HoldPlaced,
                    created_at_unix_ms,
                    tenant_id,
                });
            }
        }
        authorization
            .install_verified_invocation_admission(invocation_admission)
            .map_err(KernelError::from)?;
        let admission_evidence =
            authorization
                .invocation_admission_evidence()
                .ok_or_else(|| {
                    KernelError::Internal(
                        "threshold protocol authorization omitted admission evidence".to_string(),
                    )
                })?;
        let aggregate_binding_digest = admission_evidence
            .aggregate_binding_digest()
            .map(str::to_string);
        let aggregate_root_capability_id = admission_evidence
            .aggregate_root_capability_id()
            .map(str::to_string);
        let supplemental_verifier_id = admission_evidence
            .supplemental_verifier_id()
            .map(str::to_string);
        let supplemental_request_binding_hash = admission_evidence
            .supplemental_request_binding_hash()
            .map(str::to_string);
        let supplemental_negotiated_features_digest = admission_evidence
            .supplemental_negotiated_features_digest()
            .map(str::to_string);
        let authorization_artifact_digests =
            super::ordinary_admission::admission_authorization_artifact_digests(
                admission_evidence,
            )?;
        Ok(ThresholdBudgetAuthorization {
            request: authorization,
            aggregate_root_capability_id,
            aggregate_binding_digest,
            supplemental_verifier_id,
            supplemental_request_binding_hash,
            supplemental_negotiated_features_digest,
            authorization_artifact_digests,
        })
    }

    fn authorize_threshold_budget(
        &self,
        context: ThresholdBudgetAuthorizationContext<'_>,
        authorization: ThresholdBudgetAuthorization,
    ) -> Result<PreExecutionBudgetMutation, KernelError> {
        let ThresholdBudgetAuthorizationContext {
            capability: cap,
            grant_index,
            grant,
            operation,
            protocol,
            preexisting_operation,
        } = context;
        let expected_authority = authorization.request.authority.clone();
        let trusted_partition_escrow_evidence =
            super::ordinary_admission::authorization_partition_escrow_commit_evidence(
                &authorization.request,
                if preexisting_operation {
                    "threshold authorization replay"
                } else {
                    "threshold authorization"
                },
            )?;
        let decision = self.with_budget_store(|store| {
            let decision = if preexisting_operation {
                store
                    .replay_budget_authorization(authorization.request.clone())
                    .map_err(KernelError::from)?
            } else {
                match store.authorize_budget_hold(authorization.request.clone()) {
                    Ok(decision) => decision,
                    Err(_) => store.authorize_budget_hold(authorization.request.clone())?,
                }
            };
            let validation = self.validate_budget_authorization_decision_for_store(
                store,
                &authorization.request,
                &decision,
                &authorization.authorization_artifact_digests,
                if preexisting_operation {
                    "threshold authorization replay"
                } else {
                    "threshold authorization"
                },
            );
            Ok((decision, validation))
        })?;
        let (decision, authorization_validation) = decision;
        let BudgetAuthorizeHoldDecision::Authorized(mut authorized) = decision else {
            if authorization_validation.is_err() {
                return Err(KernelError::GuardDenied(
                    "budget authorization denial lacks exact hard-budget authority evidence"
                        .to_string(),
                ));
            }
            return Err(KernelError::BudgetExhausted(cap.id.clone()));
        };
        authorized.metadata.partition_escrow_evidence = trusted_partition_escrow_evidence;
        let admission_operation = BudgetAdmissionOperationBinding::new(
            operation.operation_id().to_string(),
            operation.request_binding_hash().to_string(),
        )?;
        let charge = self.ordinary_budget_charge(
            grant_index,
            grant,
            &protocol.hold_id,
            &authorized,
            admission_operation.clone(),
        );
        let mutation = OrdinaryAdmissionMutation {
            preexisting_operation,
            operation_id: operation.operation_id().to_string(),
            admission_operation,
            grant_index,
            hold_id: protocol.hold_id.clone(),
            reverse_event_id: protocol.reverse_event_id.clone(),
            capture_event_id: protocol.capture_event_id.clone(),
            request_binding_hash: operation.request_binding_hash().to_string(),
            aggregate_root_capability_id: authorization.aggregate_root_capability_id,
            aggregate_binding_digest: authorization.aggregate_binding_digest,
            supplemental_verifier_id: authorization.supplemental_verifier_id,
            supplemental_request_binding_hash: authorization.supplemental_request_binding_hash,
            supplemental_negotiated_features_digest: authorization
                .supplemental_negotiated_features_digest,
            authorized,
            authorization_artifact_digests: authorization.authorization_artifact_digests,
            supplemental: protocol.supplemental_plan.is_some(),
            charge,
        };
        if let Err(error) = authorization_validation {
            let cleanup_authority = (self
                .with_budget_store(|store| Ok(store.budget_guarantee_level()))?
                == crate::budget_store::BudgetGuaranteeLevel::SingleNodeAtomic)
                .then_some(expected_authority.as_ref())
                .flatten();
            self.reverse_ordinary_protocol_admission_with_authority(
                cap,
                &mutation,
                cleanup_authority,
            )?;
            return Err(error);
        }
        Ok(PreExecutionBudgetMutation::Admission(Box::new(mutation)))
    }

    fn reserve_threshold_approval_set(
        &self,
        operation_id: &str,
        approval_set: &ApprovalSetReservationInput,
    ) -> Result<ApprovalReservation, KernelError> {
        let store = self.approval_store.as_ref().ok_or_else(|| {
            KernelError::Internal("durable approval store is not installed".to_string())
        })?;
        match store.reserve_approval_set(operation_id, approval_set) {
            Ok(reservation)
                if reservation.approval_set() == approval_set
                    && reservation.state() == ReplayReservationState::Reserved =>
            {
                Ok(reservation)
            }
            Ok(_) => Err(KernelError::GovernedTransactionDenied(
                "threshold approval reservation is already terminal".to_string(),
            )),
            Err(error) => match store.get_approval_reservation(operation_id) {
                Ok(Some(reservation))
                    if reservation.approval_set() == approval_set
                        && reservation.state() == ReplayReservationState::Reserved =>
                {
                    Ok(reservation)
                }
                _ => Err(KernelError::GovernedTransactionDenied(format!(
                    "threshold approval reservation failed: {error}"
                ))),
            },
        }
    }

    fn reserve_threshold_execution_nonce(
        &self,
        operation: &AdmissionOperation,
        request: &ToolCallRequest,
    ) -> Result<Option<ExecutionNonceReservation>, KernelError> {
        let Some(presented) = request.execution_nonce.as_ref() else {
            return Ok(None);
        };
        let store = self.execution_nonce_store.as_deref().ok_or_else(|| {
            KernelError::Internal("durable execution nonce store is not installed".to_string())
        })?;
        match store.reserve_nonce_for_operation(
            operation.operation_id(),
            presented.nonce_id(),
            presented.expires_at(),
        ) {
            Ok(reservation) => Ok(Some(reservation)),
            Err(error) => match store.get_nonce_reservation(operation.operation_id()) {
                Ok(Some(reservation))
                    if reservation.nonce_id() == presented.nonce_id()
                        && reservation.signed_expires_at() == presented.expires_at() =>
                {
                    Ok(Some(reservation))
                }
                _ => Err(KernelError::GovernedTransactionDenied(format!(
                    "threshold execution nonce reservation failed: {error}"
                ))),
            },
        }
    }

    pub(super) fn commit_threshold_approval(&self, operation_id: &str) -> Result<(), KernelError> {
        let store = self.approval_store.as_ref().ok_or_else(|| {
            KernelError::Internal("durable approval store is not installed".to_string())
        })?;
        match store.commit_approval_reservation(operation_id) {
            Ok(_) => Ok(()),
            Err(error) => match store.get_approval_reservation(operation_id) {
                Ok(Some(reservation))
                    if reservation.state() == ReplayReservationState::Committed =>
                {
                    Ok(())
                }
                _ => Err(KernelError::Internal(format!(
                    "threshold approval commit failed: {error}"
                ))),
            },
        }
    }

    pub(super) fn commit_admission_execution_nonce(
        &self,
        operation: &AdmissionOperation,
    ) -> Result<(), KernelError> {
        if operation.execution_nonce_id().is_none() {
            return Ok(());
        }
        let store = self.execution_nonce_store.as_deref().ok_or_else(|| {
            KernelError::Internal("durable execution nonce store is not installed".to_string())
        })?;
        let reservation = match store.commit_nonce_reservation(operation.operation_id()) {
            Ok(reservation) => reservation,
            Err(error) => store
                .get_nonce_reservation(operation.operation_id())
                .ok()
                .flatten()
                .filter(|reservation| {
                    reservation.state() == ReplayReservationState::Committed
                        && reservation.operation_id() == operation.operation_id()
                        && operation.execution_nonce_id() == Some(reservation.nonce_id())
                })
                .ok_or_else(|| {
                    KernelError::Internal(format!(
                        "admission execution nonce commit failed: {error}"
                    ))
                })?,
        };
        if reservation.state() != ReplayReservationState::Committed
            || reservation.operation_id() != operation.operation_id()
            || operation.execution_nonce_id() != Some(reservation.nonce_id())
        {
            return Err(KernelError::Internal(
                "admission execution nonce commit returned a different reservation".to_string(),
            ));
        }
        Ok(())
    }

    fn authorize_threshold_payment_with_recovery(
        &self,
        request: &ToolCallRequest,
        budget_mutation: &PreExecutionBudgetMutation,
        payment_mode: ThresholdPaymentMode,
        verified_payee_binding: Option<&VerifiedGovernedPayeeBinding>,
    ) -> Result<Option<PaymentAuthorization>, crate::payment::PaymentAuthorizationFailure> {
        if payment_mode == ThresholdPaymentMode::CallerReservation
            && !Self::is_governed_mustprepay_request(request)
        {
            return Ok(None);
        }
        let charge = budget_mutation.charge_result();
        if Self::mustprepay_quoted_amount(request).is_none() && charge.is_none() {
            return Ok(None);
        }
        let binding = budget_mutation
            .admission_operation_binding()
            .ok_or_else(|| {
                crate::payment::PaymentAuthorizationFailure::before_rail(
                    "threshold payment recovery omitted its admission operation",
                )
            })?;
        self.authorize_payment_if_needed(request, charge, Some(binding), verified_payee_binding)
    }

    fn compensate_threshold_before_dispatch(
        &self,
        compensation: ThresholdPreDispatchCompensation<'_>,
    ) -> Result<(), KernelError> {
        let ThresholdPreDispatchCompensation { operation, reason } = compensation;
        let compensated = self
            .claim_pre_dispatch_compensation(operation.operation_id(), reason)?
            .ok_or_else(|| {
                KernelError::GovernedTransactionDenied(format!(
                    "threshold admission operation {} cannot compensate after dispatch commitment",
                    operation.operation_id()
                ))
            })?;
        if compensated.state() != AdmissionOperationState::CompensatedBeforeDispatch {
            return Err(KernelError::Internal(format!(
                "threshold admission operation {} did not finish durable compensation",
                operation.operation_id()
            )));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn release_threshold_payment_authorization(
        &self,
        request: &ToolCallRequest,
        budget_mutation: &PreExecutionBudgetMutation,
        authorization: &PaymentAuthorization,
    ) -> Result<(), KernelError> {
        let binding = budget_mutation
            .admission_operation_binding()
            .ok_or_else(|| {
                KernelError::Internal(
                    "threshold payment authorization omitted its admission operation".to_string(),
                )
            })?;
        let (amount_units, currency) = Self::mustprepay_quoted_amount(request)
            .or_else(|| {
                budget_mutation
                    .charge_result()
                    .map(|charge| (charge.cost_charged, charge.currency.clone()))
            })
            .ok_or_else(|| {
                KernelError::Internal(
                    "threshold payment authorization omitted its payment amount".to_string(),
                )
            })?;
        let adapter = self.payment_adapter.as_ref().ok_or_else(|| {
            KernelError::Internal(
                "threshold payment authorization present without configured adapter".to_string(),
            )
        })?;
        let transaction_id = if authorization.settled {
            Some(self.threshold_refund_transaction_reference(
                request,
                binding,
                authorization,
                adapter.as_ref(),
            )?)
        } else {
            None
        };
        let release = || {
            if let Some(transaction_id) = transaction_id.as_deref() {
                adapter.refund_for_operation(OperationPaymentRefundRequest {
                    operation_id: binding.operation_id(),
                    request_binding_hash: binding.request_binding_hash(),
                    transaction_id,
                    amount_units,
                    currency: &currency,
                    reference: &request.request_id,
                })
            } else {
                adapter.release_for_operation(
                    binding.operation_id(),
                    binding.request_binding_hash(),
                    &authorization.authorization_id,
                    &request.request_id,
                )
            }
        };
        release()
            .or_else(|_| release())
            .map(|_| ())
            .map_err(|error| {
                KernelError::Internal(format!(
                    "failed to release threshold payment authorization: {error}"
                ))
            })
    }

    #[cfg(test)]
    fn threshold_refund_transaction_reference(
        &self,
        request: &ToolCallRequest,
        binding: &BudgetAdmissionOperationBinding,
        authorization: &PaymentAuthorization,
        adapter: &dyn PaymentAdapter,
    ) -> Result<String, KernelError> {
        let journal = self.with_budget_store(|store| {
            store
                .get_payment_journal(&request.request_id)
                .map_err(KernelError::from)
        })?;
        let durable_transaction_id = match journal.as_ref() {
            Some(record) => {
                if record.admission_operation.as_ref() != Some(binding)
                    || record.authorization_id.as_deref()
                        != Some(authorization.authorization_id.as_str())
                {
                    return Err(KernelError::Internal(
                        "threshold payment journal does not match its refund authorization"
                            .to_string(),
                    ));
                }
                record
                    .transaction_id
                    .as_deref()
                    .filter(|value| !value.is_empty())
            }
            None => None,
        };
        let metadata_transaction_id =
            Self::payment_authorization_transaction_reference(authorization);
        if let (Some(durable), Some(metadata)) = (durable_transaction_id, metadata_transaction_id) {
            if durable != metadata {
                return Err(KernelError::Internal(
                    "threshold payment transaction references disagree".to_string(),
                ));
            }
        }
        if let Some(transaction_id) = durable_transaction_id.or(metadata_transaction_id) {
            return Ok(transaction_id.to_string());
        }

        match adapter.settlement_state_for_operation(
            binding.operation_id(),
            binding.request_binding_hash(),
            &request.request_id,
            Some(&authorization.authorization_id),
        ) {
            Ok(crate::payment::RailSettlementState::Settled {
                authorization_id,
                result,
            }) if authorization_id == authorization.authorization_id
                && !result.transaction_id.is_empty() =>
            {
                Ok(result.transaction_id)
            }
            Ok(_) => Err(KernelError::Internal(
                "settled threshold authorization has no matching transaction reference".to_string(),
            )),
            Err(error) => Err(KernelError::Internal(format!(
                "failed to resolve settled threshold payment transaction reference: {error}"
            ))),
        }
    }

    pub(super) fn cancel_threshold_approval_if_reserved(
        &self,
        operation_id: &str,
    ) -> Result<(), KernelError> {
        let Some(store) = self.approval_store.as_ref() else {
            return Ok(());
        };
        let reservation = store
            .get_approval_reservation(operation_id)
            .map_err(|error| {
                KernelError::Internal(format!(
                    "failed to inspect threshold approval reservation: {error}"
                ))
            })?;
        if !reservation
            .as_ref()
            .is_some_and(|reservation| reservation.state() == ReplayReservationState::Reserved)
        {
            return Ok(());
        }
        match store.cancel_approval_reservation(operation_id) {
            Ok(_) => Ok(()),
            Err(error) => match store.get_approval_reservation(operation_id) {
                Ok(Some(reservation))
                    if reservation.state() == ReplayReservationState::Cancelled =>
                {
                    Ok(())
                }
                _ => Err(KernelError::Internal(format!(
                    "threshold approval cancellation failed: {error}"
                ))),
            },
        }
    }

    pub(super) fn cancel_admission_nonce_if_reserved(
        &self,
        operation_id: &str,
    ) -> Result<(), KernelError> {
        let Some(store) = self.execution_nonce_store.as_deref() else {
            return Ok(());
        };
        let reservation = store.get_nonce_reservation(operation_id).map_err(|error| {
            KernelError::Internal(format!(
                "failed to inspect admission nonce reservation: {error}"
            ))
        })?;
        if !reservation
            .as_ref()
            .is_some_and(|reservation| reservation.state() == ReplayReservationState::Reserved)
        {
            return Ok(());
        }
        let cancelled = match store.cancel_nonce_reservation(operation_id) {
            Ok(cancelled) => cancelled,
            Err(error) => store
                .get_nonce_reservation(operation_id)
                .ok()
                .flatten()
                .filter(|reservation| {
                    reservation.state() == ReplayReservationState::Cancelled
                        && reservation.operation_id() == operation_id
                })
                .ok_or_else(|| {
                    KernelError::Internal(format!(
                        "admission execution nonce cancellation failed: {error}"
                    ))
                })?,
        };
        if cancelled.state() != ReplayReservationState::Cancelled
            || cancelled.operation_id() != operation_id
        {
            return Err(KernelError::Internal(
                "admission execution nonce cancellation returned a different reservation"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn threshold_cas_recover(
        &self,
        operation: &AdmissionOperation,
        next_state: AdmissionOperationState,
        next_dispatch_state: AdmissionDispatchState,
        last_error: Option<String>,
    ) -> Result<AdmissionOperation, KernelError> {
        if next_state.is_terminal() {
            return Err(KernelError::Internal(
                "terminal threshold admission transitions require an atomic signed receipt outbox"
                    .to_string(),
            ));
        }
        let store = self.admission_operation_store.as_ref().ok_or_else(|| {
            KernelError::Internal("durable admission operation store is not installed".to_string())
        })?;
        match store.compare_and_swap(AdmissionOperationCompareAndSwap {
            operation_id: operation.operation_id(),
            expected_version: operation.version(),
            coordinator_lease_epoch: operation.coordinator_lease_epoch(),
            next_state,
            next_dispatch_state,
            next_coordinator_lease_epoch: THRESHOLD_COORDINATOR_LEASE_EPOCH
                .max(operation.coordinator_lease_epoch()),
            last_error,
        }) {
            Ok(AdmissionOperationCasOutcome::Applied(next)) => Ok(next),
            Ok(AdmissionOperationCasOutcome::Conflict(current)) => Ok(current),
            Ok(AdmissionOperationCasOutcome::Missing) => Err(KernelError::Internal(
                "threshold admission operation disappeared during transition".to_string(),
            )),
            Err(error) => match store.load(operation.operation_id()) {
                Ok(Some(current)) if current.state() == next_state => Ok(current),
                _ => Err(KernelError::Internal(format!(
                    "threshold admission transition failed: {error}"
                ))),
            },
        }
    }

    pub(super) fn commit_tool_dispatch_once(
        &self,
        operation: &AdmissionOperation,
    ) -> Result<Option<AdmissionOperation>, KernelError> {
        let store = self.admission_operation_store.as_ref().ok_or_else(|| {
            KernelError::Internal("durable admission operation store is not installed".to_string())
        })?;
        match store.compare_and_swap(AdmissionOperationCompareAndSwap {
            operation_id: operation.operation_id(),
            expected_version: operation.version(),
            coordinator_lease_epoch: operation.coordinator_lease_epoch(),
            next_state: AdmissionOperationState::DispatchCommitted,
            next_dispatch_state: AdmissionDispatchState::Committed,
            next_coordinator_lease_epoch: THRESHOLD_COORDINATOR_LEASE_EPOCH
                .max(operation.coordinator_lease_epoch()),
            last_error: None,
        }) {
            Ok(AdmissionOperationCasOutcome::Applied(next)) => Ok(Some(next)),
            Ok(AdmissionOperationCasOutcome::Conflict(_)) => Ok(None),
            Ok(AdmissionOperationCasOutcome::Missing) => Err(KernelError::Internal(
                "threshold admission operation disappeared before dispatch commitment".to_string(),
            )),
            Err(error) => Err(KernelError::Internal(format!(
                "threshold dispatch commitment acknowledgement is uncertain: {error}"
            ))),
        }
    }
}
