use chio_core::capability::aggregate_budget::{
    verify_aggregate_invocation_authority, AggregateFamilyRootResolutionError,
};
use serde::Serialize;

use super::*;
use crate::admission_capture_authority::{
    project_invocation_quota_transitions, project_partition_escrow_commit_evidence,
    validate_invocation_capture_monetary_snapshot, AdmissionCaptureAuthorityProjection,
    AdmissionCaptureDecision, AdmissionCaptureError, AdmissionCaptureInvocationQuotaProjection,
    AdmissionCaptureRequest, AdmissionCaptureRequestInput,
    CombinedAdmissionCaptureReceiptProjection, PartitionEscrowCommitReceiptProjection,
};
use crate::budget_store::{
    derive_verified_invocation_admission, AuthorizedBudgetHold, BudgetAdmissionOperationBinding,
    BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest, BudgetCaptureInvocationRequest,
    BudgetCommitMetadata, BudgetGuaranteeLevel, BudgetHoldMutationDecision,
    BudgetInvocationReservationState, BudgetMonetaryHoldState, BudgetMutationKind, BudgetQuotaKey,
    BudgetReverseHoldRequest, PartitionEscrowCommitEvidence,
};
use crate::security_admission_operation::{
    AdmissionDispatchState, AdmissionOperation, AdmissionOperationCasOutcome,
    AdmissionOperationCompareAndSwap, AdmissionOperationCreateOutcome, AdmissionOperationError,
    AdmissionOperationKind, AdmissionOperationState, AdmissionRequestBindingInput,
    AdmissionRequestBindingParts, PreparedAdmissionOperation,
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

pub(super) fn admission_authorization_artifact_digests(
    evidence: crate::budget_store::BudgetInvocationAdmissionEvidence<'_>,
) -> Result<Vec<String>, KernelError> {
    let mut digests = Vec::with_capacity(2);
    if let Some(digest) = evidence.supplemental_artifact_digest() {
        digests.push(digest.to_string());
    }
    if let Some(escrow) = evidence.partition_escrow_evidence() {
        digests.push(escrow.digest().map_err(|error| {
            KernelError::Internal(format!(
                "partition escrow authorization digest failed: {error}"
            ))
        })?);
    }
    digests.sort();
    digests.dedup();
    Ok(digests)
}

pub(super) fn authorization_partition_escrow_commit_evidence(
    request: &BudgetAuthorizeHoldRequest,
    stage: &str,
) -> Result<Option<PartitionEscrowCommitEvidence>, KernelError> {
    request
        .invocation_admission_evidence()
        .ok_or_else(|| {
            KernelError::GuardDenied(format!(
                "{stage} authorization request omitted verified admission evidence"
            ))
        })?
        .partition_escrow_evidence()
        .map(PartitionEscrowCommitEvidence::from_admission_evidence)
        .transpose()
        .map_err(KernelError::from)
}

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
    #[serde(skip_serializing_if = "Option::is_none")]
    partition_escrow_evidence: Option<PartitionEscrowCommitReceiptProjection>,
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
        let partition_escrow_evidence =
            project_partition_escrow_commit_evidence(&authorized.metadata, &captured.metadata)?;
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
            partition_escrow_evidence,
            authority: AdmissionCaptureAuthorityProjection::from_budget_authority(authority)?,
            invocation_state: captured.invocation_state.as_str().to_string(),
            monetary_state: captured.monetary_state.as_str().to_string(),
        })
    }
}

pub(super) fn validate_capture_denial_partition_escrow_evidence(
    authorized: &AuthorizedBudgetHold,
    denial: &crate::admission_capture_authority::AdmissionCaptureDenial,
    stage: &str,
) -> Result<(), KernelError> {
    let denial_commit = denial.metadata().budget_commit();
    if denial_commit.authority != authorized.metadata.authority
        || denial_commit.guarantee_level != authorized.metadata.guarantee_level
        || denial_commit.budget_profile != authorized.metadata.budget_profile
        || denial_commit.metering_profile != authorized.metadata.metering_profile
    {
        return Err(KernelError::BudgetCaptureRecoveryRequired(format!(
            "{stage} budget authority did not match authorization"
        )));
    }
    project_partition_escrow_commit_evidence(&authorized.metadata, denial_commit)
        .map(|_| ())
        .map_err(|error| {
            KernelError::BudgetCaptureRecoveryRequired(format!(
                "{stage} partition escrow evidence did not match authorization: {error}"
            ))
        })
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

pub(super) struct BudgetTerminalDecisionExpectation<'a> {
    pub(super) authorization_metadata: &'a BudgetCommitMetadata,
    pub(super) expected_event_id: &'a str,
    pub(super) expected_authority: Option<&'a crate::budget_store::BudgetEventAuthority>,
    pub(super) expected_capability_id: Option<&'a str>,
    pub(super) expected_grant_index: usize,
    pub(super) expected_hold_id: &'a str,
    pub(super) expected_admission_operation: Option<&'a BudgetAdmissionOperationBinding>,
    pub(super) expected_mutation_kind: BudgetMutationKind,
    pub(super) expected_exposure_units: u64,
    pub(super) expected_realized_spend_units: u64,
    pub(super) expected_invocation_state: BudgetInvocationReservationState,
    pub(super) expected_monetary_state: BudgetMonetaryHoldState,
    pub(super) stage: &'a str,
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
    fn validate_cumulative_approval_ordinary_admission(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        grant_index: usize,
        grant: &ToolGrant,
        now: u64,
    ) -> Result<(), KernelError> {
        let cumulative_constraint_count = grant
            .constraints
            .iter()
            .filter(|constraint| {
                matches!(
                    constraint,
                    Constraint::RequireCumulativeApprovalAbove { .. }
                )
            })
            .count();
        if cumulative_constraint_count == 0 {
            return Ok(());
        }
        if cumulative_constraint_count != 1 {
            return Err(KernelError::GovernedTransactionDenied(
                "a matching grant must contain exactly one cumulative approval constraint"
                    .to_string(),
            ));
        }

        let peer = self
            .capability_negotiation_for_remote(request.federated_origin_kernel_id.as_deref(), now)
            .map_err(KernelError::GovernedTransactionDenied)?;
        if !peer.supports(chio_core::capability::features::CUMULATIVE_APPROVAL_BUDGET) {
            return Err(KernelError::GovernedTransactionDenied(
                "cumulative approval budgets were not negotiated".to_string(),
            ));
        }
        let direct_root = self
            .negotiated_capability_root(cap, &peer)
            .map_err(KernelError::GovernedTransactionDenied)?;
        let trusted = self
            .trusted_issuer_keys_for(cap, now)
            .map_err(KernelError::GovernedTransactionDenied)?;
        let verified =
            chio_core::capability::cumulative_approval::verify_cumulative_approval_constraints(
                cap,
                &trusted,
                direct_root.as_ref(),
            )
            .map_err(|error| KernelError::GovernedTransactionDenied(error.to_string()))?;
        let mut matching_constraints = verified
            .into_iter()
            .filter(|constraint| constraint.grant_index == grant_index);
        let constraint = matching_constraints.next().ok_or_else(|| {
            KernelError::GovernedTransactionDenied(
                "cumulative approval verification omitted the matching grant".to_string(),
            )
        })?;
        if matching_constraints.next().is_some() {
            return Err(KernelError::GovernedTransactionDenied(
                "cumulative approval verification produced an ambiguous grant".to_string(),
            ));
        }

        let governed_intent = request.governed_intent.as_ref().ok_or_else(|| {
            KernelError::GovernedTransactionDenied(
                "cumulative approval requires a governed transaction intent".to_string(),
            )
        })?;
        let intent = governed_intent.as_tool_invocation().ok_or_else(|| {
            KernelError::GovernedTransactionDenied(
                "cumulative approval requires a governed tool-invocation intent".to_string(),
            )
        })?;
        if intent.server_id != request.server_id || intent.tool_name != request.tool_name {
            return Err(KernelError::GovernedTransactionDenied(
                "cumulative approval intent target does not match the request".to_string(),
            ));
        }
        let requested_authorized = intent.max_amount.as_ref().ok_or_else(|| {
            KernelError::GovernedTransactionDenied(
                "cumulative approval intent requires a maximum amount".to_string(),
            )
        })?;
        if requested_authorized.currency != constraint.threshold.currency {
            return Err(KernelError::GovernedTransactionDenied(
                "cumulative approval intent currency does not match the capability".to_string(),
            ));
        }

        Err(KernelError::GovernedTransactionDenied(
            "cumulative approval requires a qualified admission authority; the ordinary durable admission participant is unavailable"
                .to_string(),
        ))
    }

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
        self.validate_cumulative_approval_ordinary_admission(
            request,
            cap,
            grant_index,
            grant,
            now,
        )?;
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
        let prepared = AdmissionOperation::prepared(PreparedAdmissionOperation {
            kind: AdmissionOperationKind::ToolDispatch,
            coordinator_authority_id: format!("kernel:{}", self.public_key().to_hex()),
            request_id: request.request_id.clone(),
            capability_id: cap.id.clone(),
            authorization_capability_hash: capability_digest.clone(),
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
        let operation_store = self.admission_operation_store.as_ref().ok_or_else(|| {
            KernelError::Internal("durable admission operation store is unavailable".to_string())
        })?;
        let (mut operation, preexisting_operation) =
            match operation_store.create_prepared(prepared)? {
                AdmissionOperationCreateOutcome::Created(operation) => (operation, false),
                AdmissionOperationCreateOutcome::Existing(operation) => (operation, true),
            };
        if preexisting_operation {
            return self.replay_existing_ordinary_protocol_admission(
                operation_store.as_ref(),
                operation,
                cap,
                grant_index,
                grant,
                &hold_id,
                &authorize_event_id,
                &reverse_event_id,
                &capture_event_id,
                &request_binding_hash,
            );
        }
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
        let authority = self.budget_event_authority();
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
        let authorization_artifact_digests =
            admission_authorization_artifact_digests(admission_evidence)?;
        let trusted_partition_escrow_evidence =
            authorization_partition_escrow_commit_evidence(&authorization, "authorization")?;
        let decision = match self.with_budget_store(|store| {
            let decision = store
                .authorize_budget_hold(authorization.clone())
                .or_else(|_| store.authorize_budget_hold(authorization.clone()))
                .map_err(KernelError::from)?;
            let validation = self.validate_budget_authorization_decision_for_store(
                store,
                &authorization,
                &decision,
                &authorization_artifact_digests,
                "authorization",
            );
            Ok((decision, validation))
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
        let (decision, authorization_validation) = decision;
        let BudgetAuthorizeHoldDecision::Authorized(mut authorized) = decision else {
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
            if authorization_validation.is_err() {
                return Err(KernelError::GuardDenied(
                    "budget authorization denial lacks exact hard-budget authority evidence"
                        .to_string(),
                ));
            }
            return Err(KernelError::BudgetExhausted(cap.id.clone()));
        };
        authorized.metadata.partition_escrow_evidence = trusted_partition_escrow_evidence;
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
        if let Err(error) = authorization_validation {
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

    #[allow(clippy::too_many_arguments)]
    fn replay_existing_ordinary_protocol_admission(
        &self,
        operation_store: &dyn crate::security_admission_operation::AdmissionOperationStore,
        mut operation: AdmissionOperation,
        cap: &CapabilityToken,
        expected_grant_index: usize,
        grant: &ToolGrant,
        expected_hold_id: &str,
        expected_authorize_event_id: &str,
        expected_reverse_event_id: &str,
        expected_capture_event_id: &str,
        expected_request_binding_hash: &str,
    ) -> Result<PreExecutionBudgetMutation, KernelError> {
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
                "admission operation {} cannot replay authorization from {}",
                operation.operation_id(),
                operation.state().as_str()
            )));
        }
        let snapshot = self.load_recovery_budget_snapshot(operation_store, &operation)?;
        if snapshot.hold_id() != expected_hold_id
            || snapshot.reverse_event_id() != expected_reverse_event_id
            || snapshot.capture_event_id() != expected_capture_event_id
            || snapshot.request_binding_hash() != expected_request_binding_hash
        {
            return Err(KernelError::GuardDenied(
                "existing admission changed its frozen budget participant binding".to_string(),
            ));
        }
        let authorization = snapshot.authorization_request()?;
        let expected_admission_operation = BudgetAdmissionOperationBinding::new(
            operation.operation_id().to_string(),
            operation.request_binding_hash().to_string(),
        )?;
        if authorization.capability_id != cap.id
            || authorization.grant_index != expected_grant_index
            || authorization.event_id.as_deref() != Some(expected_authorize_event_id)
            || authorization.hold_id.as_deref() != Some(expected_hold_id)
            || authorization.admission_operation.as_ref() != Some(&expected_admission_operation)
        {
            return Err(KernelError::GuardDenied(
                "existing admission changed its frozen budget authorization".to_string(),
            ));
        }
        let admission_evidence =
            authorization
                .invocation_admission_evidence()
                .ok_or_else(|| {
                    KernelError::Internal(
                        "existing budget authorization omitted frozen admission evidence"
                            .to_string(),
                    )
                })?;
        let aggregate_root_capability_id = admission_evidence
            .aggregate_root_capability_id()
            .map(str::to_string);
        let aggregate_binding_digest = admission_evidence
            .aggregate_binding_digest()
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
        let supplemental = admission_evidence.supplemental_artifact_digest().is_some();
        let authorization_artifact_digests = snapshot.authorization_artifact_digests();
        let decision = self.with_budget_store(|store| {
            let decision = store
                .replay_budget_authorization(authorization.clone())
                .map_err(KernelError::from)?;
            let validation = self.validate_budget_authorization_decision_for_store(
                store,
                &authorization,
                &decision,
                &authorization_artifact_digests,
                "authorization replay",
            );
            Ok((decision, validation))
        })?;
        let (decision, authorization_validation) = decision;
        let BudgetAuthorizeHoldDecision::Authorized(authorized) = decision else {
            if authorization_validation.is_err() {
                return Err(KernelError::GuardDenied(
                    "budget authorization denial lacks exact hard-budget authority evidence"
                        .to_string(),
                ));
            }
            return Err(KernelError::BudgetExhausted(cap.id.clone()));
        };
        let admission_operation = expected_admission_operation;
        let charge = self.ordinary_budget_charge(
            authorization.grant_index,
            grant,
            expected_hold_id,
            &authorized,
            admission_operation.clone(),
        );
        let mutation = OrdinaryAdmissionMutation {
            preexisting_operation: true,
            operation_id: operation.operation_id().to_string(),
            admission_operation,
            grant_index: authorization.grant_index,
            hold_id: expected_hold_id.to_string(),
            reverse_event_id: expected_reverse_event_id.to_string(),
            capture_event_id: expected_capture_event_id.to_string(),
            request_binding_hash: expected_request_binding_hash.to_string(),
            aggregate_root_capability_id,
            aggregate_binding_digest,
            supplemental_verifier_id,
            supplemental_request_binding_hash,
            supplemental_negotiated_features_digest,
            authorized,
            authorization_artifact_digests,
            supplemental,
            charge,
        };
        authorization_validation?;
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
}

include!("ordinary_admission_tail.inc");

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
