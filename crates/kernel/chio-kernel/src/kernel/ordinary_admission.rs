use chio_core::capability::aggregate_budget::{
    verify_aggregate_invocation_authority, AggregateFamilyRootResolutionError,
};
use serde::Serialize;

use super::*;
use crate::admission_capture_authority::{
    project_invocation_quota_transitions, validate_invocation_capture_monetary_snapshot,
    AdmissionCaptureAuthorityProjection, AdmissionCaptureDecision, AdmissionCaptureError,
    AdmissionCaptureInvocationQuotaProjection, AdmissionCaptureRequest,
    AdmissionCaptureRequestInput, CombinedAdmissionCaptureReceiptProjection,
};
use crate::admission_operation::{
    AdmissionDispatchState, AdmissionOperation, AdmissionOperationCasOutcome,
    AdmissionOperationCompareAndSwap, AdmissionOperationCreateOutcome, AdmissionOperationError,
    AdmissionOperationKind, AdmissionOperationState, AdmissionRequestBindingInput,
    AdmissionRequestBindingParts, PreparedAdmissionOperation,
};
use crate::budget_store::{
    derive_verified_invocation_admission, AuthorizedBudgetHold, BudgetAdmissionOperationBinding,
    BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest, BudgetCaptureInvocationRequest,
    BudgetCommitMetadata, BudgetGuaranteeLevel, BudgetInvocationReservationState,
    BudgetReverseHoldRequest,
};
use crate::supplemental_quota::{
    OpaqueSignedSupplementalQuota, SupplementalAdmissionAuthorization,
    SupplementalAdmissionPrepareRequest, SupplementalQuotaDestination,
    SupplementalQuotaVerificationContext,
};

const ORDINARY_COORDINATOR_LEASE_EPOCH: u64 = 1;
const ORDINARY_REQUEST_FINGERPRINT_SCHEMA: &str = "chio.ordinary-request-fingerprint.v1";
const ORDINARY_REQUEST_FINGERPRINT_DOMAIN: &[u8] = b"chio.ordinary-request-fingerprint.v1\0";
const MAX_ORDINARY_DESTINATION_IDENTIFIER_BYTES: usize = 512;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OrdinaryRequestFingerprintBody<'a> {
    schema: &'static str,
    request_id: &'a str,
    capability_id: &'a str,
    capability_subject: &'a str,
    capability_digest: &'a str,
    server_id: &'a str,
    tool_name: &'a str,
    agent_id: &'a str,
    arguments_digest: &'a str,
    dpop_digest: Option<&'a str>,
    model_metadata_digest: Option<&'a str>,
    federated_origin_kernel_id: Option<&'a str>,
    governed_intent_digest: Option<&'a str>,
    threshold_proposal_digest: Option<&'a str>,
    approval_token_digests: &'a [String],
    supplemental_authorization_reference: Option<&'a str>,
    supplemental_authorization_digest: Option<&'a str>,
    execution_nonce_reference: Option<&'a str>,
    execution_nonce_digest: Option<&'a str>,
    declassification_grant_digest: Option<&'a str>,
    trusted_tenant_id: Option<&'a str>,
    caller_receipt_metadata_digest: Option<&'a str>,
    policy_hash: &'a str,
}

fn normalized_ordinary_destination_identifier<'a>(
    value: &'a str,
    label: &str,
) -> Result<&'a str, KernelError> {
    let normalized = value.trim();
    if normalized.is_empty()
        || normalized != value
        || normalized.len() > MAX_ORDINARY_DESTINATION_IDENTIFIER_BYTES
        || normalized.bytes().any(|byte| byte == 0)
    {
        return Err(KernelError::GuardDenied(format!(
            "{label} is empty, oversized, padded, or contains NUL"
        )));
    }
    Ok(normalized)
}

fn canonical_ordinary_request_component_digest<T: Serialize>(
    value: &T,
    label: &str,
) -> Result<String, KernelError> {
    canonical_json_bytes(value)
        .map(|canonical| sha256_hex(&canonical))
        .map_err(|error| {
            KernelError::GuardDenied(format!(
                "{label} failed canonical ordinary request binding: {error}"
            ))
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OrdinaryProtocolCaptureMode {
    InlineDispatch,
    ThresholdDispatch,
    CallerReservationOrdinary,
    CallerReservationThreshold,
}

#[allow(clippy::large_enum_variant)]
enum OrdinaryProtocolCaptureOutcome {
    DispatchMetadata(serde_json::Value),
    CallerReservation(CallerReservationCaptureOutcome),
}

impl OrdinaryProtocolCaptureMode {
    fn pending_state(self) -> AdmissionOperationState {
        match self {
            Self::InlineDispatch | Self::ThresholdDispatch => {
                AdmissionOperationState::CapturePending
            }
            Self::CallerReservationOrdinary | Self::CallerReservationThreshold => {
                AdmissionOperationState::CallerReservationCapturePending
            }
        }
    }

    fn prepares_supplemental_dispatch(self) -> bool {
        !matches!(
            self,
            Self::ThresholdDispatch | Self::CallerReservationThreshold
        )
    }

    fn commits_presented_replay_reservations(self) -> bool {
        matches!(
            self,
            Self::InlineDispatch
                | Self::CallerReservationOrdinary
                | Self::CallerReservationThreshold
        )
    }

    fn label(self) -> &'static str {
        match self {
            Self::InlineDispatch => "ordinary",
            Self::ThresholdDispatch => "threshold",
            Self::CallerReservationOrdinary => "caller reservation",
            Self::CallerReservationThreshold => "threshold caller reservation",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct BudgetInvocationCaptureReceiptProjection {
    operation_id: String,
    hold_id: String,
    event_id: String,
    invocation_quotas: Vec<AdmissionCaptureInvocationQuotaProjection>,
    budget_commit_index: u64,
    guarantee_level: String,
    authority: AdmissionCaptureAuthorityProjection,
    invocation_state: String,
    monetary_state: String,
}

impl BudgetInvocationCaptureReceiptProjection {
    pub(super) fn from_capture(
        operation_id: &str,
        authorized: &AuthorizedBudgetHold,
        captured: &crate::budget_store::BudgetHoldMutationDecision,
    ) -> Result<Self, AdmissionCaptureError> {
        let hold_id = captured.hold_id.as_deref().ok_or_else(|| {
            AdmissionCaptureError::InvalidRequest(
                "budget capture projection requires a hold_id".to_string(),
            )
        })?;
        let event_id = captured.metadata.event_id.as_deref().ok_or_else(|| {
            AdmissionCaptureError::InvalidRequest(
                "budget capture projection requires an event_id".to_string(),
            )
        })?;
        if operation_id.is_empty()
            || authorized.hold_id.as_deref() != Some(hold_id)
            || authorized.invocation_state != BudgetInvocationReservationState::Authorized
            || captured.invocation_state != BudgetInvocationReservationState::Captured
            || captured.invocation_count_after != authorized.invocation_count_after
            || captured.monetary_state != authorized.monetary_state
            || captured.metadata.authority != authorized.metadata.authority
            || captured.metadata.guarantee_level != authorized.metadata.guarantee_level
            || captured.metadata.budget_profile != authorized.metadata.budget_profile
            || captured.metadata.metering_profile != authorized.metadata.metering_profile
        {
            return Err(AdmissionCaptureError::InvalidRequest(
                "budget capture projection does not match the authorization snapshot".to_string(),
            ));
        }
        validate_invocation_capture_monetary_snapshot(authorized, captured)?;
        let budget_commit_index = captured.metadata.budget_commit_index.ok_or_else(|| {
            AdmissionCaptureError::InvalidRequest(
                "budget capture projection requires a budget commit index".to_string(),
            )
        })?;
        if budget_commit_index == 0
            || authorized
                .metadata
                .budget_commit_index
                .is_none_or(|index| index == 0 || index >= budget_commit_index)
        {
            return Err(AdmissionCaptureError::InvalidRequest(
                "budget capture projection commit index did not advance".to_string(),
            ));
        }
        let authority = captured.metadata.authority.as_ref().ok_or_else(|| {
            AdmissionCaptureError::InvalidRequest(
                "budget capture projection requires fenced authority evidence".to_string(),
            )
        })?;
        Ok(Self {
            operation_id: operation_id.to_string(),
            hold_id: hold_id.to_string(),
            event_id: event_id.to_string(),
            invocation_quotas: project_invocation_quota_transitions(
                &authorized.invocation_counts_after,
                &captured.invocation_counts_after,
            )?,
            budget_commit_index,
            guarantee_level: captured.metadata.guarantee_level.as_str().to_string(),
            authority: AdmissionCaptureAuthorityProjection::from_budget_authority(authority)?,
            invocation_state: captured.invocation_state.as_str().to_string(),
            monetary_state: captured.monetary_state.as_str().to_string(),
        })
    }
}

pub(crate) struct OrdinaryAdmissionMutation {
    pub(super) preexisting_operation: bool,
    pub(super) operation_id: String,
    pub(super) admission_operation: BudgetAdmissionOperationBinding,
    pub(super) grant_index: usize,
    pub(super) hold_id: String,
    pub(super) reverse_event_id: String,
    pub(super) capture_event_id: String,
    pub(super) request_binding_hash: String,
    pub(super) aggregate_root_capability_id: Option<String>,
    pub(super) aggregate_binding_digest: Option<String>,
    pub(super) supplemental_verifier_id: Option<String>,
    pub(super) supplemental_request_binding_hash: Option<String>,
    pub(super) supplemental_negotiated_features_digest: Option<String>,
    pub(super) authorized: AuthorizedBudgetHold,
    pub(super) authorization_artifact_digests: Vec<String>,
    pub(super) supplemental: bool,
    pub(super) charge: Option<BudgetChargeResult>,
}

impl OrdinaryAdmissionMutation {
    pub(crate) fn charge_result(&self) -> Option<&BudgetChargeResult> {
        self.charge.as_ref()
    }

    pub(crate) fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub(super) fn preexisting_operation(&self) -> bool {
        self.preexisting_operation
    }

    pub(crate) fn admission_operation(&self) -> &BudgetAdmissionOperationBinding {
        &self.admission_operation
    }
}

impl ChioKernel {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn coordinate_ordinary_protocol_admission(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        grant_index: usize,
        grant: &ToolGrant,
        caller_reservation: bool,
        caller_receipt_metadata: Option<&serde_json::Value>,
        now: u64,
    ) -> Result<PreExecutionBudgetMutation, KernelError> {
        self.validate_protocol_admission_runtime(cap, request)?;
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

        let capability_digest = crate::threshold_approval::authorization_capability_hash(cap)
            .map_err(|error| KernelError::GuardDenied(error.to_string()))?;
        let arguments_digest =
            sha256_hex(&canonical_json_bytes(&request.arguments).map_err(|error| {
                KernelError::GuardDenied(format!(
                    "tool arguments failed canonical admission binding: {error}"
                ))
            })?);
        let supplemental_artifact = request
            .supplemental_authorization
            .as_ref()
            .map(|authorization| {
                OpaqueSignedSupplementalQuota::new(authorization.artifact().to_vec())
                    .map_err(|error| KernelError::GuardDenied(error.to_string()))
            })
            .transpose()?;
        let supplemental_plan = match (
            request.supplemental_authorization.as_ref(),
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
                    "budget-hold:{}:{}:{grant_index}",
                    request.request_id, cap.id
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
            .map(OpaqueSignedSupplementalQuota::digest);
        let request_binding_hash = self.ordinary_request_binding_hash_for_policy(
            request,
            &hold_id,
            supplemental_digest.as_deref(),
            caller_receipt_metadata,
            &self.config.policy_hash,
        )?;
        let supplemental = match supplemental_artifact.as_ref() {
            Some(artifact) => Some(
                self.verify_supplemental_quota(
                    artifact,
                    &SupplementalQuotaVerificationContext {
                        capability_id: cap.id.clone(),
                        capability_digest: capability_digest.clone(),
                        subject: cap.subject.clone(),
                        request_id: request.request_id.clone(),
                        destination: SupplementalQuotaDestination::new(
                            request.server_id.clone(),
                            request.tool_name.clone(),
                        )
                        .map_err(|error| KernelError::GuardDenied(error.to_string()))?,
                        arguments_digest: arguments_digest.clone(),
                        request_binding_hash: request_binding_hash.clone(),
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
        let authority = self.local_budget_event_authority();
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
            Some(hold_id.clone()),
            Some(authorize_event_id.clone()),
            Some(authority.clone()),
        );
        authorization.install_verified_invocation_admission(invocation_admission)?;

        let prepared = AdmissionOperation::prepared(PreparedAdmissionOperation {
            kind: AdmissionOperationKind::ToolDispatch,
            coordinator_authority_id: format!("kernel:{}", self.public_key().to_hex()),
            request_id: request.request_id.clone(),
            capability_id: cap.id.clone(),
            authorization_capability_hash: capability_digest,
            request_binding_hash: request_binding_hash.clone(),
            policy_hash: self.config.policy_hash.clone(),
            broker_attempt_id: supplemental_plan
                .as_ref()
                .map(|plan| plan.attempt_id().to_string()),
            budget_hold_id: Some(hold_id.clone()),
            approval_set_hash: None,
            execution_nonce_id: request
                .execution_nonce
                .as_ref()
                .map(|nonce| nonce.nonce_id().to_string()),
            coordinator_lease_epoch: ORDINARY_COORDINATOR_LEASE_EPOCH,
        })?;
        let budget_operation = BudgetAdmissionOperationBinding::new(
            prepared.operation_id().to_string(),
            prepared.request_binding_hash().to_string(),
        )?;
        authorization.admission_operation = Some(budget_operation.clone());
        if self.payment_journal_active()
            && (!caller_reservation || Self::is_governed_mustprepay_request(request))
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
                    admission_operation: Some(budget_operation.clone()),
                    authority: Some(authority.clone()),
                    hold_id: Some(hold_id.clone()),
                    rail,
                    authorization_id: None,
                    transaction_id: None,
                    budget_exposure_units: cost_units,
                    amount_units,
                    settle_action: None,
                    settle_amount_units: None,
                    currency,
                    state: crate::payment::PaymentJournalState::HoldPlaced,
                    created_at_unix_ms,
                    tenant_id,
                });
            }
        }
        let operation_store = self.admission_operation_store.as_ref().ok_or_else(|| {
            KernelError::Internal("durable admission operation store is unavailable".to_string())
        })?;
        let (mut operation, preexisting_operation) =
            match operation_store.create_prepared(prepared)? {
                AdmissionOperationCreateOutcome::Created(operation) => (operation, false),
                AdmissionOperationCreateOutcome::Existing(operation) => (operation, true),
            };
        self.journal_budget_cleanup(
            &operation,
            &authorization,
            reverse_event_id.clone(),
            capture_event_id.clone(),
        )?;
        if let Some(attempt_id) = operation.broker_attempt_id() {
            self.journal_broker_cleanup(&operation, attempt_id.to_string())?;
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
                    "ordinary admission operation {} has cleanup owned by another worker",
                    operation.operation_id()
                )));
            }
            operation = operation_store
                .load(operation.operation_id())?
                .ok_or_else(|| {
                    KernelError::Internal(
                        "ordinary admission disappeared after compensation recovery".to_string(),
                    )
                })?;
        }
        if !matches!(
            operation.state(),
            AdmissionOperationState::Prepared
                | AdmissionOperationState::BrokerAttemptRegistered
                | AdmissionOperationState::BudgetAuthorized
                | AdmissionOperationState::ReadyToDispatch
                | AdmissionOperationState::CapturePending
        ) {
            return Err(KernelError::GuardDenied(format!(
                "admission operation {} cannot authorize from {}",
                operation.operation_id(),
                operation.state().as_str()
            )));
        }

        if operation.state() == AdmissionOperationState::Prepared {
            if let Some(plan) = supplemental_plan.as_ref() {
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
                        &authorization,
                    ),
                ) {
                    let terminal = self.claim_pre_dispatch_compensation(
                        operation.operation_id(),
                        &error.to_string(),
                    )?;
                    if terminal.is_none() {
                        return Err(KernelError::Internal(
                            "broker registration failure lost the compensation-dispatch race"
                                .to_string(),
                        ));
                    }
                    let _ = registrar.release_admission(operation.operation_id());
                    return Err(KernelError::GuardDenied(error.to_string()));
                }
                operation = self.ordinary_admission_transition(
                    &operation,
                    AdmissionOperationState::BrokerAttemptRegistered,
                    AdmissionDispatchState::NotStarted,
                    None,
                )?;
            }
        }

        let admission_evidence =
            authorization
                .invocation_admission_evidence()
                .ok_or_else(|| {
                    KernelError::Internal(
                        "ordinary protocol authorization omitted admission evidence".to_string(),
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
        let decision = match self.with_budget_store(|store| {
            store
                .authorize_budget_hold(authorization.clone())
                .or_else(|_| store.authorize_budget_hold(authorization))
                .map_err(KernelError::from)
        }) {
            Ok(decision) => decision,
            Err(error)
                if matches!(
                    operation.state(),
                    AdmissionOperationState::Prepared
                        | AdmissionOperationState::BrokerAttemptRegistered
                ) =>
            {
                if self
                    .claim_pre_dispatch_compensation(operation.operation_id(), &error.to_string())?
                    .is_none()
                {
                    return Err(KernelError::Internal(
                        "budget authorization failure lost the compensation-dispatch race"
                            .to_string(),
                    ));
                }
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        let BudgetAuthorizeHoldDecision::Authorized(authorized) = decision else {
            if self
                .claim_pre_dispatch_compensation(
                    operation.operation_id(),
                    "composite budget exhausted",
                )?
                .is_some()
            {
                if let Some(registrar) = self.supplemental_admission_registrar.as_ref() {
                    let _ = registrar.release_admission(operation.operation_id());
                }
            }
            return Err(KernelError::BudgetExhausted(cap.id.clone()));
        };
        let charge = self.ordinary_budget_charge(
            grant_index,
            grant,
            &hold_id,
            &authorized,
            budget_operation.clone(),
        );
        if self.payment_adapter.is_some()
            && (!caller_reservation || Self::is_governed_mustprepay_request(request))
        {
            let payment_terms = charge
                .as_ref()
                .map(|charge| (charge.cost_charged, charge.currency.clone()))
                .or_else(|| Self::mustprepay_quoted_amount(request));
            if let Some((amount_units, currency)) = payment_terms {
                self.journal_payment_cleanup(
                    &operation,
                    amount_units,
                    currency,
                    request.request_id.clone(),
                )?;
            }
        }
        let authorization_artifact_digests = supplemental_digest.into_iter().collect();
        let mutation = OrdinaryAdmissionMutation {
            preexisting_operation,
            operation_id: operation.operation_id().to_string(),
            admission_operation: budget_operation,
            grant_index,
            hold_id,
            reverse_event_id,
            capture_event_id,
            request_binding_hash,
            aggregate_root_capability_id,
            aggregate_binding_digest,
            supplemental_verifier_id,
            supplemental_request_binding_hash,
            supplemental_negotiated_features_digest,
            authorized,
            authorization_artifact_digests,
            supplemental: supplemental_plan.is_some(),
            charge,
        };
        if let Err(error) = self.validate_hard_budget_commit_metadata(
            &mutation.authorized.metadata,
            &authorize_event_id,
            Some(&authority),
            None,
            "authorization",
        ) {
            // Choose cleanup authority from the trusted store topology, never
            // from metadata the authority just returned. A single-node store
            // must reverse with the request authority even when the returned
            // authority field was forged. HA must use the remotely assigned
            // lease returned by authorization.
            let cleanup_authority = (self
                .with_budget_store(|store| Ok(store.budget_guarantee_level()))?
                == BudgetGuaranteeLevel::SingleNodeAtomic)
                .then_some(&authority);
            self.reverse_ordinary_protocol_admission_with_authority(
                cap,
                &mutation,
                cleanup_authority,
            )?;
            return Err(error);
        }
        if matches!(
            operation.state(),
            AdmissionOperationState::Prepared | AdmissionOperationState::BrokerAttemptRegistered
        ) {
            let _ = self.ordinary_admission_transition(
                &operation,
                AdmissionOperationState::BudgetAuthorized,
                AdmissionDispatchState::NotStarted,
                None,
            )?;
        }
        Ok(PreExecutionBudgetMutation::Admission(Box::new(mutation)))
    }

    pub(super) fn validate_protocol_admission_runtime(
        &self,
        cap: &CapabilityToken,
        request: &ToolCallRequest,
    ) -> Result<(), KernelError> {
        if cap.aggregate_invocation_budget.is_some() && !self.aggregate_invocation_admission_enabled
        {
            return Err(KernelError::GuardDenied(
                "aggregate invocation budget is not enabled".to_string(),
            ));
        }
        if request.supplemental_authorization.is_some()
            && !self.supplemental_broker_admission_enabled
        {
            return Err(KernelError::GuardDenied(
                "supplemental broker admission is not enabled".to_string(),
            ));
        }
        self.validate_protocol_budget_admission_profiles()
    }

    pub(super) fn ordinary_request_binding_hash_for_policy(
        &self,
        request: &ToolCallRequest,
        hold_id: &str,
        supplemental_digest: Option<&str>,
        caller_receipt_metadata: Option<&serde_json::Value>,
        policy_hash: &str,
    ) -> Result<String, KernelError> {
        let governed_intent_hash = request
            .governed_intent
            .as_ref()
            .map(chio_core::capability::governance::GovernedTransactionIntent::binding_hash)
            .transpose()
            .map_err(|error| KernelError::GuardDenied(error.to_string()))?;
        let threshold_proposal_hash = request
            .threshold_approval_proposal
            .as_ref()
            .map(|proposal| canonical_json_bytes(proposal).map(|bytes| sha256_hex(&bytes)))
            .transpose()
            .map_err(|error| KernelError::GuardDenied(error.to_string()))?;
        let mut approval_token_digests = Vec::new();
        for token in request.normalized_approval_tokens()? {
            approval_token_digests.push(
                token
                    .token_digest()
                    .map_err(|error| KernelError::GuardDenied(error.to_string()))?,
            );
        }
        let request_fingerprint =
            self.ordinary_request_fingerprint_hash(request, policy_hash, caller_receipt_metadata)?;
        AdmissionRequestBindingInput::from_unordered_approval_token_digests(
            AdmissionRequestBindingParts {
                action_hash: request_fingerprint,
                policy_hash: policy_hash.to_string(),
                governed_intent_hash,
                threshold_proposal_hash,
                verified_approval_set_hash: None,
                approval_token_digests,
                budget_hold_reference: Some(hold_id.to_string()),
                supplemental_authorization_reference: request
                    .supplemental_authorization
                    .as_ref()
                    .map(|authorization| authorization.reference().to_string()),
                supplemental_authorization_digest: supplemental_digest.map(str::to_string),
                execution_nonce_reference: request
                    .execution_nonce
                    .as_ref()
                    .map(|nonce| nonce.nonce_id().to_string()),
            },
        )
        .and_then(|binding| binding.derive_hash())
        .map_err(|error| KernelError::Internal(error.to_string()))
    }

    pub(super) fn ordinary_request_fingerprint_hash(
        &self,
        request: &ToolCallRequest,
        policy_hash: &str,
        caller_receipt_metadata: Option<&serde_json::Value>,
    ) -> Result<String, KernelError> {
        let server_id = normalized_ordinary_destination_identifier(
            &request.server_id,
            "ordinary request server_id",
        )?;
        let tool_name = normalized_ordinary_destination_identifier(
            &request.tool_name,
            "ordinary request tool_name",
        )?;
        let capability_subject = request.capability.subject.to_hex();
        let capability_digest = canonical_ordinary_request_component_digest(
            &request.capability,
            "authorizing capability",
        )?;
        let arguments_digest =
            canonical_ordinary_request_component_digest(&request.arguments, "tool arguments")?;
        let dpop_digest = request
            .dpop_proof
            .as_ref()
            .map(|proof| canonical_ordinary_request_component_digest(proof, "DPoP proof"))
            .transpose()?;
        let model_metadata_digest = request
            .model_metadata
            .as_ref()
            .map(|metadata| canonical_ordinary_request_component_digest(metadata, "model metadata"))
            .transpose()?;
        let governed_intent_digest = request
            .governed_intent
            .as_ref()
            .map(chio_core::capability::governance::GovernedTransactionIntent::binding_hash)
            .transpose()
            .map_err(|error| {
                KernelError::GuardDenied(format!(
                    "governed intent failed ordinary request binding: {error}"
                ))
            })?;
        let threshold_proposal_digest = request
            .threshold_approval_proposal
            .as_ref()
            .map(|proposal| {
                canonical_ordinary_request_component_digest(proposal, "threshold proposal")
            })
            .transpose()?;
        let mut approval_token_digests = request
            .normalized_approval_tokens()?
            .iter()
            .map(|token| {
                token
                    .token_digest()
                    .map_err(|error| KernelError::GuardDenied(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        approval_token_digests.sort_unstable();
        let supplemental_authorization_reference = request
            .supplemental_authorization
            .as_ref()
            .map(chio_core::OpaqueSupplementalAuthorization::reference);
        let supplemental_authorization_digest = request
            .supplemental_authorization
            .as_ref()
            .map(|authorization| sha256_hex(authorization.artifact()));
        let execution_nonce_reference = request
            .execution_nonce
            .as_ref()
            .map(crate::execution_nonce::SignedExecutionNonce::nonce_id);
        let execution_nonce_digest = request
            .execution_nonce
            .as_ref()
            .map(|nonce| {
                canonical_ordinary_request_component_digest(nonce, "presented execution nonce")
            })
            .transpose()?;
        let declassification_grant_digest = request
            .declassification_grant
            .as_ref()
            .map(|grant| {
                canonical_ordinary_request_component_digest(grant, "declassification grant")
            })
            .transpose()?;
        let caller_receipt_metadata_digest = caller_receipt_metadata
            .map(|metadata| {
                canonical_ordinary_request_component_digest(metadata, "caller receipt metadata")
            })
            .transpose()?;
        let trusted_tenant_id = self
            .receipt_tenant_id_for_request(Some(&request.request_id))
            .unwrap_or_else(current_scoped_receipt_tenant_id);
        let canonical = canonical_json_bytes(&OrdinaryRequestFingerprintBody {
            schema: ORDINARY_REQUEST_FINGERPRINT_SCHEMA,
            request_id: &request.request_id,
            capability_id: &request.capability.id,
            capability_subject: &capability_subject,
            capability_digest: &capability_digest,
            server_id,
            tool_name,
            agent_id: &request.agent_id,
            arguments_digest: &arguments_digest,
            dpop_digest: dpop_digest.as_deref(),
            model_metadata_digest: model_metadata_digest.as_deref(),
            federated_origin_kernel_id: request.federated_origin_kernel_id.as_deref(),
            governed_intent_digest: governed_intent_digest.as_deref(),
            threshold_proposal_digest: threshold_proposal_digest.as_deref(),
            approval_token_digests: &approval_token_digests,
            supplemental_authorization_reference,
            supplemental_authorization_digest: supplemental_authorization_digest.as_deref(),
            execution_nonce_reference,
            execution_nonce_digest: execution_nonce_digest.as_deref(),
            declassification_grant_digest: declassification_grant_digest.as_deref(),
            trusted_tenant_id: trusted_tenant_id.as_deref(),
            caller_receipt_metadata_digest: caller_receipt_metadata_digest.as_deref(),
            policy_hash,
        })
        .map_err(|error| {
            KernelError::GuardDenied(format!(
                "ordinary request fingerprint canonicalization failed: {error}"
            ))
        })?;
        let mut domain_separated =
            Vec::with_capacity(ORDINARY_REQUEST_FINGERPRINT_DOMAIN.len() + canonical.len());
        domain_separated.extend_from_slice(ORDINARY_REQUEST_FINGERPRINT_DOMAIN);
        domain_separated.extend_from_slice(&canonical);
        Ok(sha256_hex(&domain_separated))
    }

    pub(super) fn ordinary_budget_charge(
        &self,
        grant_index: usize,
        grant: &ToolGrant,
        hold_id: &str,
        authorized: &AuthorizedBudgetHold,
        admission_operation: BudgetAdmissionOperationBinding,
    ) -> Option<BudgetChargeResult> {
        let (cost_charged, currency) = self.ordinary_payment_charge_terms(grant)?;
        Some(BudgetChargeResult {
            grant_index,
            cost_charged,
            currency,
            budget_total: grant
                .max_total_cost
                .as_ref()
                .map_or(u64::MAX, |amount| amount.units),
            new_committed_cost_units: authorized.committed_cost_units_after,
            budget_hold_id: hold_id.to_string(),
            authorize_metadata: authorized.metadata.clone(),
            admission_operation: Some(admission_operation),
        })
    }

    pub(super) fn ordinary_payment_charge_terms(&self, grant: &ToolGrant) -> Option<(u64, String)> {
        let has_monetary =
            grant.max_cost_per_invocation.is_some() || grant.max_total_cost.is_some();
        has_monetary.then(|| {
            (
                grant
                    .max_cost_per_invocation
                    .as_ref()
                    .map_or(0, |amount| amount.units),
                grant
                    .max_cost_per_invocation
                    .as_ref()
                    .map(|amount| amount.currency.clone())
                    .or_else(|| {
                        grant
                            .max_total_cost
                            .as_ref()
                            .map(|amount| amount.currency.clone())
                    })
                    .unwrap_or_else(|| "USD".to_string()),
            )
        })
    }

    pub(super) fn commit_ordinary_protocol_dispatch(
        &self,
        cap: &CapabilityToken,
        mutation: &OrdinaryAdmissionMutation,
    ) -> Result<serde_json::Value, KernelError> {
        match self.commit_protocol_capture(
            cap,
            mutation,
            OrdinaryProtocolCaptureMode::InlineDispatch,
        )? {
            OrdinaryProtocolCaptureOutcome::DispatchMetadata(metadata) => Ok(metadata),
            OrdinaryProtocolCaptureOutcome::CallerReservation(_) => Err(KernelError::Internal(
                "ordinary dispatch returned a caller reservation capture".to_string(),
            )),
        }
    }

    pub(super) fn commit_threshold_protocol_dispatch(
        &self,
        cap: &CapabilityToken,
        mutation: &OrdinaryAdmissionMutation,
    ) -> Result<serde_json::Value, KernelError> {
        match self.commit_protocol_capture(
            cap,
            mutation,
            OrdinaryProtocolCaptureMode::ThresholdDispatch,
        )? {
            OrdinaryProtocolCaptureOutcome::DispatchMetadata(metadata) => Ok(metadata),
            OrdinaryProtocolCaptureOutcome::CallerReservation(_) => Err(KernelError::Internal(
                "threshold dispatch returned a caller reservation capture".to_string(),
            )),
        }
    }

    /// Capture an operation-owned composite admission for a caller-mediated
    /// execution. The caller must keep the exact hold stamped and the signed
    /// execution nonce private until this returns: `CallerReserved` is the
    /// durable handoff boundary after which startup recovery may not compensate
    /// the captured invocation reservations.
    pub(super) fn commit_ordinary_protocol_caller_reservation(
        &self,
        cap: &CapabilityToken,
        mutation: &OrdinaryAdmissionMutation,
    ) -> Result<CallerReservationCaptureOutcome, KernelError> {
        match self.commit_protocol_capture(
            cap,
            mutation,
            OrdinaryProtocolCaptureMode::CallerReservationOrdinary,
        )? {
            OrdinaryProtocolCaptureOutcome::CallerReservation(capture) => Ok(capture),
            OrdinaryProtocolCaptureOutcome::DispatchMetadata(_) => Err(KernelError::Internal(
                "ordinary caller reservation returned dispatch metadata".to_string(),
            )),
        }
    }

    pub(super) fn commit_threshold_protocol_caller_reservation(
        &self,
        cap: &CapabilityToken,
        mutation: &OrdinaryAdmissionMutation,
    ) -> Result<CallerReservationCaptureOutcome, KernelError> {
        match self.commit_protocol_capture(
            cap,
            mutation,
            OrdinaryProtocolCaptureMode::CallerReservationThreshold,
        )? {
            OrdinaryProtocolCaptureOutcome::CallerReservation(capture) => Ok(capture),
            OrdinaryProtocolCaptureOutcome::DispatchMetadata(_) => Err(KernelError::Internal(
                "threshold caller reservation returned dispatch metadata".to_string(),
            )),
        }
    }

    fn commit_protocol_capture(
        &self,
        cap: &CapabilityToken,
        mutation: &OrdinaryAdmissionMutation,
        mode: OrdinaryProtocolCaptureMode,
    ) -> Result<OrdinaryProtocolCaptureOutcome, KernelError> {
        let mut operation = self.load_ordinary_admission(mutation.operation_id())?;
        if operation.state() == AdmissionOperationState::BudgetAuthorized {
            operation = self.ordinary_admission_transition(
                &operation,
                AdmissionOperationState::ReadyToDispatch,
                AdmissionDispatchState::NotStarted,
                None,
            )?;
        }
        if operation.state() == AdmissionOperationState::ReadyToDispatch {
            if mutation.supplemental && mode.prepares_supplemental_dispatch() {
                let registrar =
                    self.supplemental_admission_registrar
                        .as_ref()
                        .ok_or_else(|| {
                            KernelError::Internal(
                                "supplemental admission registrar disappeared before dispatch"
                                    .to_string(),
                            )
                        })?;
                if let Err(error) = registrar.prepare_dispatch(operation.operation_id()) {
                    self.reverse_ordinary_protocol_admission(cap, mutation)?;
                    return Err(KernelError::GuardDenied(error.to_string()));
                }
            }
            operation = self.ordinary_admission_transition(
                &operation,
                mode.pending_state(),
                AdmissionDispatchState::NotStarted,
                None,
            )?;
        }
        if operation.state() != mode.pending_state() {
            return Err(KernelError::GuardDenied(format!(
                "admission operation {} cannot capture from {}",
                operation.operation_id(),
                operation.state().as_str()
            )));
        }
        if matches!(
            mode,
            OrdinaryProtocolCaptureMode::CallerReservationOrdinary
                | OrdinaryProtocolCaptureMode::CallerReservationThreshold
        ) && operation.approval_set_hash().is_some()
        {
            if let Err(error) = self.commit_threshold_approval(operation.operation_id()) {
                self.reverse_ordinary_protocol_admission_from_capture_pending(
                    cap,
                    mutation,
                    &error.to_string(),
                )?;
                return Err(error);
            }
            self.discharge_admission_cleanup_action(
                &operation,
                crate::admission_operation::AdmissionCleanupActionKind::Approval,
            )?;
        }
        if mode.commits_presented_replay_reservations() {
            let replay_commit = self
                .commit_admission_execution_nonce(&operation)
                .and_then(|()| {
                    if operation.execution_nonce_id().is_some() {
                        self.discharge_admission_cleanup_action(
                            &operation,
                            crate::admission_operation::AdmissionCleanupActionKind::ExecutionNonce,
                        )?;
                    }
                    Ok(())
                });
            if let Err(error) = replay_commit {
                self.reverse_ordinary_protocol_admission_from_capture_pending(
                    cap,
                    mutation,
                    &error.to_string(),
                )?;
                return Err(error);
            }
        }
        let capture_request = BudgetCaptureInvocationRequest {
            capability_id: cap.id.clone(),
            grant_index: mutation.grant_index,
            hold_id: Some(mutation.hold_id.clone()),
            event_id: Some(mutation.capture_event_id.clone()),
            authority: mutation.authorized.metadata.authority.clone(),
            admission_operation: Some(BudgetAdmissionOperationBinding::new(
                mutation.operation_id.clone(),
                mutation.request_binding_hash.clone(),
            )?),
        };
        let capture_metadata = if mutation.supplemental {
            let revocation_set = mutation.authorized.revocation_set.clone().ok_or_else(|| {
                KernelError::Internal("supplemental hold omitted its revocation set".to_string())
            })?;
            let request = AdmissionCaptureRequest::new(AdmissionCaptureRequestInput {
                operation_id: operation.operation_id().to_string(),
                budget: capture_request,
                revocation_set: revocation_set.clone(),
                bound_revocation_set_digest: revocation_set.digest().to_string(),
                authorization_artifact_digests: mutation.authorization_artifact_digests.clone(),
                aggregate_root_capability_id: mutation.aggregate_root_capability_id.clone(),
                aggregate_root_binding_digest: mutation.aggregate_binding_digest.clone(),
                last_observed_revocation_index: None,
            })?;
            let authority = self.admission_capture_authority.as_ref().ok_or_else(|| {
                KernelError::Internal("admission capture authority is unavailable".to_string())
            })?;
            let decision = authority
                .query_admission_capture(&request)
                .and_then(|existing| match existing {
                    Some(decision) => Ok(decision),
                    None => authority.capture_admission(request.clone()),
                })
                .map_err(|error| KernelError::BudgetCaptureRecoveryRequired(error.to_string()))?;
            match decision {
                AdmissionCaptureDecision::Captured { budget, metadata } => {
                    if budget.invocation_state != BudgetInvocationReservationState::Captured {
                        return Err(KernelError::BudgetCaptureRecoveryRequired(
                            "combined authority did not capture invocation reservations"
                                .to_string(),
                        ));
                    }
                    if let Err(error) = self.validate_hard_budget_commit_metadata(
                        &budget.metadata,
                        &mutation.capture_event_id,
                        mutation.authorized.metadata.authority.as_ref(),
                        mutation.authorized.metadata.budget_commit_index,
                        "combined capture",
                    ) {
                        // Captured reservations cannot be reversed truthfully.
                        // Leave the durable operation in its capture-pending
                        // state so an exact retry can re-query and validate
                        // without a second effect.
                        return Err(KernelError::BudgetCaptureRecoveryRequired(
                            error.to_string(),
                        ));
                    }
                    if metadata.checked_revocation_set_digest() != revocation_set.digest()
                        || metadata.aggregate_root_capability_id()
                            != mutation.aggregate_root_capability_id.as_deref()
                        || metadata.aggregate_root_binding_digest()
                            != mutation.aggregate_binding_digest.as_deref()
                    {
                        return Err(KernelError::BudgetCaptureRecoveryRequired(
                            "combined capture metadata does not match the verified admission evidence"
                                .to_string(),
                        ));
                    }
                    let projection = CombinedAdmissionCaptureReceiptProjection::from_capture(
                        &request,
                        &mutation.authorized,
                        &budget,
                        &metadata,
                    )?;
                    serde_json::to_value(projection).map_err(|error| {
                        KernelError::Internal(format!(
                            "authoritative admission capture projection serialization failed: {error}"
                        ))
                    })?
                }
                AdmissionCaptureDecision::Denied(denial) => {
                    self.reverse_ordinary_protocol_admission_from_capture_pending(
                        cap,
                        mutation,
                        "capture authority definitively denied admission",
                    )?;
                    return Err(KernelError::CapabilityRevoked(
                        denial.revoked_ids().join(","),
                    ));
                }
            }
        } else {
            let captured = self
                .with_budget_store(|store| {
                    store
                        .capture_invocation_reservations(capture_request.clone())
                        .or_else(|_| store.capture_invocation_reservations(capture_request))
                        .map_err(KernelError::from)
                })
                .map_err(|error| KernelError::BudgetCaptureRecoveryRequired(error.to_string()))?;
            if captured.invocation_state != BudgetInvocationReservationState::Captured {
                return Err(KernelError::BudgetCaptureRecoveryRequired(
                    "budget authority did not capture invocation reservations".to_string(),
                ));
            }
            if let Err(error) = self.validate_hard_budget_commit_metadata(
                &captured.metadata,
                &mutation.capture_event_id,
                mutation.authorized.metadata.authority.as_ref(),
                mutation.authorized.metadata.budget_commit_index,
                "capture",
            ) {
                // Captured reservations cannot be reversed truthfully. Keep
                // the mode-specific pending state for idempotent authority
                // recovery.
                return Err(KernelError::BudgetCaptureRecoveryRequired(
                    error.to_string(),
                ));
            }
            let projection = BudgetInvocationCaptureReceiptProjection::from_capture(
                operation.operation_id(),
                &mutation.authorized,
                &captured,
            )?;
            serde_json::to_value(projection).map_err(|error| {
                KernelError::Internal(format!(
                    "budget invocation capture projection serialization failed: {error}"
                ))
            })?
        };
        match mode {
            OrdinaryProtocolCaptureMode::InlineDispatch => {
                operation = self.commit_tool_dispatch_once(&operation)?.ok_or_else(|| {
                    KernelError::GovernedTransactionDenied(format!(
                        "{} admission operation {} was committed by another coordinator",
                        mode.label(),
                        operation.operation_id()
                    ))
                })?;
            }
            OrdinaryProtocolCaptureMode::ThresholdDispatch => {}
            OrdinaryProtocolCaptureMode::CallerReservationOrdinary
            | OrdinaryProtocolCaptureMode::CallerReservationThreshold => {
                let reserved = operation.transition_checked(
                    AdmissionOperationState::CallerReserved,
                    AdmissionDispatchState::Committed,
                    operation.coordinator_lease_epoch(),
                    None,
                )?;
                return Ok(OrdinaryProtocolCaptureOutcome::CallerReservation(
                    CallerReservationCaptureOutcome {
                        current: operation,
                        reserved,
                        capture_metadata,
                    },
                ));
            }
        }
        Ok(OrdinaryProtocolCaptureOutcome::DispatchMetadata(
            self.ordinary_admission_receipt_metadata(mutation, &operation, capture_metadata),
        ))
    }

    pub(super) fn bind_threshold_dispatch_receipt_operation(
        &self,
        mutation: &OrdinaryAdmissionMutation,
        operation: &AdmissionOperation,
        capture_receipt: &serde_json::Value,
    ) -> Result<serde_json::Value, KernelError> {
        let capture = capture_receipt
            .pointer("/protocol_admission/invocation_capture")
            .cloned()
            .ok_or_else(|| {
                KernelError::Internal(
                    "threshold capture receipt omitted invocation metadata".to_string(),
                )
            })?;
        Ok(self.ordinary_admission_receipt_metadata(mutation, operation, capture))
    }

    pub(crate) fn reverse_ordinary_protocol_admission(
        &self,
        cap: &CapabilityToken,
        mutation: &OrdinaryAdmissionMutation,
    ) -> Result<crate::budget_store::BudgetReverseHoldDecision, KernelError> {
        self.reverse_ordinary_protocol_admission_inner(cap, mutation, None, None)
    }

    pub(super) fn reverse_ordinary_protocol_admission_with_authority(
        &self,
        cap: &CapabilityToken,
        mutation: &OrdinaryAdmissionMutation,
        cleanup_authority: Option<&crate::budget_store::BudgetEventAuthority>,
    ) -> Result<crate::budget_store::BudgetReverseHoldDecision, KernelError> {
        self.reverse_ordinary_protocol_admission_inner(cap, mutation, cleanup_authority, None)
    }

    pub(super) fn reverse_ordinary_protocol_admission_from_capture_pending(
        &self,
        cap: &CapabilityToken,
        mutation: &OrdinaryAdmissionMutation,
        reason: &str,
    ) -> Result<crate::budget_store::BudgetReverseHoldDecision, KernelError> {
        self.reverse_ordinary_protocol_admission_inner(cap, mutation, None, Some(reason))
    }

    fn reverse_ordinary_protocol_admission_inner(
        &self,
        cap: &CapabilityToken,
        mutation: &OrdinaryAdmissionMutation,
        cleanup_authority: Option<&crate::budget_store::BudgetEventAuthority>,
        capture_pending_compensation_reason: Option<&str>,
    ) -> Result<crate::budget_store::BudgetReverseHoldDecision, KernelError> {
        let claim = if let Some(reason) = capture_pending_compensation_reason {
            self.claim_capture_pending_compensation(mutation.operation_id(), reason)
        } else {
            self.claim_pre_dispatch_compensation(
                mutation.operation_id(),
                "pre-dispatch admission reversed",
            )
        }?;
        let operation = claim.ok_or_else(|| {
            KernelError::GovernedTransactionDenied(format!(
                "admission operation {} cannot reverse after capture began or dispatch committed",
                mutation.operation_id()
            ))
        })?;
        let reversed = self.with_budget_store(|store| {
            let request = BudgetReverseHoldRequest {
                capability_id: cap.id.clone(),
                grant_index: mutation.grant_index,
                reversed_exposure_units: mutation
                    .charge_result()
                    .map_or(0, |charge| charge.cost_charged),
                hold_id: Some(mutation.hold_id.clone()),
                event_id: Some(mutation.reverse_event_id.clone()),
                authority: cleanup_authority
                    .cloned()
                    .or_else(|| mutation.authorized.metadata.authority.clone()),
                admission_operation: Some(BudgetAdmissionOperationBinding::new(
                    mutation.operation_id.clone(),
                    mutation.request_binding_hash.clone(),
                )?),
            };
            store
                .reverse_budget_hold(request.clone())
                .or_else(|_| store.reverse_budget_hold(request))
                .map_err(KernelError::from)
        })?;
        if operation.approval_set_hash().is_some() {
            self.cancel_threshold_approval_if_reserved(operation.operation_id())?;
        }
        if operation.execution_nonce_id().is_some() {
            self.cancel_admission_nonce_if_reserved(operation.operation_id())?;
        }
        if mutation.supplemental {
            if let Some(registrar) = self.supplemental_admission_registrar.as_ref() {
                registrar
                    .release_admission(mutation.operation_id())
                    .map_err(|error| KernelError::Internal(error.to_string()))?;
            }
        }
        Ok(reversed)
    }

    pub(super) fn ordinary_admission_receipt_metadata(
        &self,
        mutation: &OrdinaryAdmissionMutation,
        operation: &AdmissionOperation,
        capture: serde_json::Value,
    ) -> serde_json::Value {
        let quotas: Vec<serde_json::Value> = mutation
            .authorized
            .invocation_counts_after
            .iter()
            .map(|usage| {
                serde_json::json!({
                    "profile": usage.quota.key().profile().as_str(),
                    "owner_id": usage.quota.key().owner_id(),
                    "grant_index": usage.quota.key().grant_index(),
                    "max_invocations": usage.quota.max_invocations(),
                    "reserved_invocations_after": usage.reserved_invocations_after,
                    "captured_invocations_after": usage.captured_invocations_after,
                })
            })
            .collect();
        serde_json::json!({
            "protocol_admission": {
                "hold_id": mutation.hold_id,
                "request_binding_hash": mutation.request_binding_hash,
                "guarantee_level": mutation.authorized.metadata.guarantee_level.as_str(),
                "authority_profile": mutation.authorized.metadata.budget_profile.as_str(),
                "metering_profile": mutation.authorized.metadata.metering_profile.as_str(),
                "aggregate_family_preservation": mutation
                    .aggregate_binding_digest
                    .as_ref()
                    .zip(mutation.aggregate_root_capability_id.as_ref())
                    .map(|(root_binding_digest, root_capability_id)| serde_json::json!({
                        "root_capability_id": root_capability_id,
                        "root_binding_digest": root_binding_digest,
                    })),
                "supplemental_verifier_id": mutation.supplemental_verifier_id,
                "supplemental_request_binding_hash": mutation
                    .supplemental_request_binding_hash,
                "supplemental_negotiated_features_digest": mutation
                    .supplemental_negotiated_features_digest,
                "authorize": {
                    "event_id": mutation.authorized.metadata.event_id,
                    "budget_commit_index": mutation.authorized.metadata.budget_commit_index,
                    "invocation_state": mutation.authorized.invocation_state.as_str(),
                    "monetary_state": mutation.authorized.monetary_state.as_str(),
                    "invocation_quotas": quotas,
                    "revocation_set_digest": mutation
                        .authorized
                        .revocation_set
                        .as_ref()
                        .map(crate::supplemental_quota::CanonicalRevocationSet::digest),
                    "authorization_artifact_digests": mutation.authorization_artifact_digests,
                },
                "invocation_capture": capture,
                "admission_operation": {
                    "operation_id": operation.operation_id(),
                    "state": operation.state().as_str(),
                    "dispatch_state": operation.dispatch_state().as_str(),
                    "version": operation.version(),
                }
            }
        })
    }

    pub(super) fn ordinary_admission_operation_metadata(
        &self,
        operation: &AdmissionOperation,
    ) -> serde_json::Value {
        serde_json::json!({
            "protocol_admission": {
                "admission_operation": {
                    "operation_id": operation.operation_id(),
                    "state": operation.state().as_str(),
                    "dispatch_state": operation.dispatch_state().as_str(),
                    "version": operation.version(),
                    "last_error": operation.last_error(),
                }
            }
        })
    }

    pub(super) fn validate_hard_budget_commit_metadata(
        &self,
        metadata: &BudgetCommitMetadata,
        expected_event_id: &str,
        expected_authority: Option<&crate::budget_store::BudgetEventAuthority>,
        prior_commit_index: Option<u64>,
        stage: &str,
    ) -> Result<(), KernelError> {
        self.with_budget_store(|store| {
            self.validate_hard_budget_commit_metadata_for_store(
                store,
                metadata,
                expected_event_id,
                expected_authority,
                prior_commit_index,
                stage,
            )
        })
    }

    pub(super) fn validate_hard_budget_commit_metadata_for_store(
        &self,
        store: &dyn crate::budget_store::BudgetStore,
        metadata: &BudgetCommitMetadata,
        expected_event_id: &str,
        expected_authority: Option<&crate::budget_store::BudgetEventAuthority>,
        prior_commit_index: Option<u64>,
        stage: &str,
    ) -> Result<(), KernelError> {
        let store_profile = store.authority_profile();
        let configured_guarantee = store.budget_guarantee_level();
        let configured_authority_profile = store.budget_authority_profile();
        let configured_metering_profile = store.budget_metering_profile();
        let authority_is_valid = match metadata.guarantee_level {
            BudgetGuaranteeLevel::SingleNodeAtomic => {
                metadata.authority.as_ref() == expected_authority
            }
            BudgetGuaranteeLevel::HaLinearizable => {
                metadata.authority.as_ref().is_some_and(|authority| {
                    !authority.authority_id.is_empty()
                        && !authority.lease_id.is_empty()
                        && authority.lease_epoch > 0
                        && (prior_commit_index.is_none()
                            || metadata.authority.as_ref() == expected_authority)
                })
            }
            BudgetGuaranteeLevel::PartitionEscrowed | BudgetGuaranteeLevel::AdvisoryPosthoc => {
                false
            }
        };
        if metadata.guarantee_level != configured_guarantee
            || metadata.budget_profile != configured_authority_profile
            || metadata.metering_profile != configured_metering_profile
            || !metadata
                .guarantee_level
                .supports_hard_invocation_limit(store_profile, self.dispatch_worker_count)
            || metadata.event_id.as_deref() != Some(expected_event_id)
            || !authority_is_valid
        {
            return Err(KernelError::GuardDenied(format!(
                "{stage} budget commit metadata cannot enforce the configured hard invocation limit"
            )));
        }
        if metadata.authority.is_none()
            || metadata
                .budget_commit_index
                .is_none_or(|commit_index| commit_index == 0)
        {
            return Err(KernelError::GuardDenied(format!(
                "{stage} hard budget commit omitted fenced authority evidence"
            )));
        }
        if let (Some(previous), Some(current)) = (prior_commit_index, metadata.budget_commit_index)
        {
            if current <= previous {
                return Err(KernelError::GuardDenied(format!(
                    "{stage} budget commit index did not advance"
                )));
            }
        } else if prior_commit_index.is_some() {
            return Err(KernelError::GuardDenied(format!(
                "{stage} hard budget commit omitted its monotonic commit index"
            )));
        }
        Ok(())
    }

    pub(super) fn load_ordinary_admission(
        &self,
        operation_id: &str,
    ) -> Result<AdmissionOperation, KernelError> {
        self.admission_operation_store
            .as_ref()
            .ok_or_else(|| {
                KernelError::Internal("admission operation store is unavailable".to_string())
            })?
            .load(operation_id)?
            .ok_or_else(|| {
                KernelError::Internal(format!("admission operation {operation_id} disappeared"))
            })
    }

    fn ordinary_admission_transition(
        &self,
        operation: &AdmissionOperation,
        next_state: AdmissionOperationState,
        next_dispatch_state: AdmissionDispatchState,
        last_error: Option<String>,
    ) -> Result<AdmissionOperation, KernelError> {
        if next_state.is_terminal() {
            return Err(KernelError::Internal(
                "terminal ordinary admission transitions require an atomic signed receipt outbox"
                    .to_string(),
            ));
        }
        let store = self.admission_operation_store.as_ref().ok_or_else(|| {
            KernelError::Internal("admission operation store is unavailable".to_string())
        })?;
        match store.compare_and_swap(AdmissionOperationCompareAndSwap {
            operation_id: operation.operation_id(),
            expected_version: operation.version(),
            coordinator_lease_epoch: operation.coordinator_lease_epoch(),
            next_state,
            next_dispatch_state,
            next_coordinator_lease_epoch: ORDINARY_COORDINATOR_LEASE_EPOCH
                .max(operation.coordinator_lease_epoch()),
            last_error,
        }) {
            Ok(AdmissionOperationCasOutcome::Applied(next)) => Ok(next),
            Ok(AdmissionOperationCasOutcome::Conflict(current))
                if current.state() == next_state =>
            {
                Ok(current)
            }
            Ok(AdmissionOperationCasOutcome::Conflict(current)) => {
                Err(KernelError::Internal(format!(
                    "admission transition conflicted at {}",
                    current.state().as_str()
                )))
            }
            Ok(AdmissionOperationCasOutcome::Missing) => Err(KernelError::Internal(
                "admission operation disappeared during transition".to_string(),
            )),
            Err(error) => match store.load(operation.operation_id()) {
                Ok(Some(current)) if current.state() == next_state => Ok(current),
                _ => Err(KernelError::Internal(format!(
                    "admission transition acknowledgement is uncertain: {error}"
                ))),
            },
        }
    }

    /// Win or recover the durable compensation branch before mutating any
    /// participant. The dispatch CAS and this CAS share the same operation
    /// version, so exactly one terminal direction can become authoritative.
    /// A durable compensated record is safe to resume because every downstream
    /// release is operation-bound and idempotent.
    pub(super) fn claim_pre_dispatch_compensation(
        &self,
        operation_id: &str,
        reason: &str,
    ) -> Result<Option<AdmissionOperation>, KernelError> {
        self.claim_pre_dispatch_compensation_inner(operation_id, reason, false)
    }

    fn claim_capture_pending_compensation(
        &self,
        operation_id: &str,
        reason: &str,
    ) -> Result<Option<AdmissionOperation>, KernelError> {
        self.claim_pre_dispatch_compensation_inner(operation_id, reason, true)
    }

    fn claim_pre_dispatch_compensation_inner(
        &self,
        operation_id: &str,
        reason: &str,
        capture_cannot_have_committed: bool,
    ) -> Result<Option<AdmissionOperation>, KernelError> {
        let store = self.admission_operation_store.as_ref().ok_or_else(|| {
            KernelError::Internal("admission operation store is unavailable".to_string())
        })?;
        let current = store.load(operation_id)?.ok_or_else(|| {
            KernelError::Internal(format!("admission operation {operation_id} disappeared"))
        })?;
        if matches!(
            current.state(),
            AdmissionOperationState::CompensationPending
                | AdmissionOperationState::CompensatedBeforeDispatch
        ) {
            if !self.recover_compensated_admission_operation(current.operation_id())? {
                return Err(KernelError::Internal(format!(
                    "admission operation {} has cleanup owned by another recovery worker",
                    current.operation_id()
                )));
            }
            let terminal = store.load(current.operation_id())?.ok_or_else(|| {
                KernelError::Internal(
                    "admission operation disappeared after compensation recovery".to_string(),
                )
            })?;
            return Ok(Some(terminal));
        }
        // Both capture-pending states are uncertainty boundaries. A capture
        // may already be committed while its acknowledgement is in flight, so
        // generic cleanup cannot claim either one. Only a caller that has not
        // entered the capture authority yet, or an exact authority-returned
        // Denied decision, may cross this boundary into compensation.
        if matches!(
            current.state(),
            AdmissionOperationState::CapturePending
                | AdmissionOperationState::CallerReservationCapturePending
        ) && !capture_cannot_have_committed
        {
            return Ok(None);
        }
        if current.dispatch_state() != AdmissionDispatchState::NotStarted
            || matches!(
                current.state(),
                AdmissionOperationState::DispatchCommitted
                    | AdmissionOperationState::CallerReserved
                    | AdmissionOperationState::Completed
                    | AdmissionOperationState::OutcomeUnknownAfterDispatch
            )
        {
            return Ok(None);
        }
        let current = self.stage_compensation_pending_with_terminal_receipt(
            store.as_ref(),
            &current,
            reason,
        )?;
        if !self.recover_compensated_admission_operation(current.operation_id())? {
            return Err(KernelError::Internal(format!(
                "admission operation {} has cleanup owned by another recovery worker",
                current.operation_id()
            )));
        }
        let terminal = store.load(current.operation_id())?.ok_or_else(|| {
            KernelError::Internal(
                "admission operation disappeared after compensation terminalization".to_string(),
            )
        })?;
        Ok(Some(terminal))
    }
}

impl From<AdmissionOperationError> for KernelError {
    fn from(error: AdmissionOperationError) -> Self {
        match error {
            AdmissionOperationError::Conflict(reason) => Self::CallerReservationConflict(reason),
            error => Self::Internal(format!("admission operation failed: {error}")),
        }
    }
}

impl From<AdmissionCaptureError> for KernelError {
    fn from(error: AdmissionCaptureError) -> Self {
        Self::Internal(format!("admission capture failed: {error}"))
    }
}
