use serde::{Deserialize, Serialize};

use super::ordinary_admission::BudgetInvocationCaptureReceiptProjection;
use super::*;
use crate::admission_capture_authority::{
    AdmissionCaptureDecision, AdmissionCaptureRequest, AdmissionCaptureRequestInput,
    CombinedAdmissionCaptureReceiptProjection,
};
use crate::admission_operation::{
    AdmissionCleanupAction, AdmissionCleanupActionCasOutcome, AdmissionCleanupActionClaimOutcome,
    AdmissionCleanupActionCreateOutcome, AdmissionCleanupActionKind, AdmissionCleanupActionState,
    AdmissionDispatchState, AdmissionOperation, AdmissionOperationCasOutcome,
    AdmissionOperationCompareAndSwap, AdmissionOperationKind, AdmissionOperationState,
    AdmissionOperationStore, ReplayReservationState,
};
use crate::approval::ApprovalStore;
use crate::budget_store::{
    AuthorizedBudgetHold, BudgetAuthorityProfile, BudgetCommitMetadata, BudgetEventAuthority,
    BudgetGuaranteeLevel, BudgetHoldDispositionView, BudgetInvocationQuota,
    BudgetInvocationQuotaUsage, BudgetInvocationReservationState, BudgetMeteringProfile,
    BudgetMonetaryHoldState, BudgetQuotaKey, BudgetQuotaProfile, BudgetStore,
    PartitionEscrowCommitEvidence,
};
use crate::execution_nonce::{is_supported_execution_nonce_schema, SignedExecutionNonce};
use crate::payment::{PaymentJournalRecord, PaymentJournalState};

const CALLER_RESERVATION_HANDOFF_INTENT_SCHEMA: &str = "chio.caller-reservation-handoff-intent.v1";
const CALLER_RESERVATION_HANDOFF_INTENT_DOMAIN: &str =
    "chio.caller-reservation-handoff-intent.v1\0";
const CALLER_RESERVATION_HANDOFF_SCHEMA: &str = "chio.caller-reservation-handoff.v1";
const MAX_CALLER_RESERVATION_REQUEST_CANDIDATES: usize = 2;
const CALLER_RESERVATION_DELIVERY_CLAIM_LEASE_MS: u64 = 30_000;

/// Result of a read-before-admit exact caller-reservation replay probe.
/// `Conflict` deliberately reveals no operation or handoff details.
#[allow(clippy::large_enum_variant)]
pub enum CallerReservationReplayProbe {
    Absent,
    Conflict,
    Replayed(ToolCallResponse),
}

/// Authenticated outcome of the public caller-reservation authorization
/// entrypoint. Adapters use this marker to avoid duplicating their own receipt
/// log and request-id ownership effects when the kernel returned an exact
/// durable replay.
pub enum CallerReservationAuthorizationOutcome {
    Authorized(ToolCallResponse),
    Replayed(ToolCallResponse),
}

impl CallerReservationAuthorizationOutcome {
    pub fn into_response(self) -> ToolCallResponse {
        match self {
            Self::Authorized(response) | Self::Replayed(response) => response,
        }
    }
}

pub(super) struct PrepareCallerReservationHandoff<'a> {
    pub(super) request: &'a ToolCallRequest,
    pub(super) timestamp: u64,
    pub(super) matched_grant_index: usize,
    pub(super) admission: &'a OrdinaryAdmissionMutation,
    pub(super) response_metadata: Option<serde_json::Value>,
    pub(super) caller_receipt_metadata: Option<&'a serde_json::Value>,
    pub(super) incomplete_reason: &'a str,
}

pub(super) struct CallerReservationCaptureOutcome {
    pub(super) current: AdmissionOperation,
    pub(super) reserved: AdmissionOperation,
    pub(super) capture_metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SignedCallerReservationHandoffIntent {
    body: CallerReservationHandoffIntentBody,
    signature: chio_core::crypto::Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CallerReservationHandoffIntentBody {
    schema: String,
    operation_id: String,
    request_binding_hash: String,
    request_fingerprint_hash: String,
    request_snapshot_hash: String,
    request_id: String,
    capability_id: String,
    authorization_capability_hash: String,
    matched_grant_index: usize,
    hold_id: String,
    policy_hash: String,
    tool_server: String,
    tool_name: String,
    agent_id: String,
    capability_subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    trusted_tenant_id: Option<String>,
    caller_receipt_metadata_hash: String,
    requires_settled_prepayment: bool,
    federation_admission: ReceiptFederationAdmission,
    signer_identity: chio_core::crypto::PublicKey,
    receipt_id: String,
    content_hash: String,
    timestamp: u64,
    expires_at: i64,
    incomplete_reason: String,
    action: ToolCallAction,
    base_receipt_metadata: Option<serde_json::Value>,
    guard_evidence: Vec<GuardEvidence>,
    protocol_admission_base: serde_json::Value,
    authorization: CallerReservationAuthorizationProjection,
    execution_nonce: SignedExecutionNonce,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CallerReservationHandoffIntentSigningEnvelope<'a> {
    domain: &'static str,
    body: &'a CallerReservationHandoffIntentBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CallerReservationHandoffPayload {
    schema: String,
    intent_action_id: String,
    intent_payload_hash: String,
    operation_id: String,
    request_binding_hash: String,
    request_fingerprint_hash: String,
    request_id: String,
    capability_id: String,
    authorization_capability_hash: String,
    matched_grant_index: usize,
    hold_id: String,
    policy_hash: String,
    signer_identity: chio_core::crypto::PublicKey,
    tool_server: String,
    tool_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    trusted_tenant_id: Option<String>,
    timestamp: u64,
    expires_at: i64,
    incomplete_reason: String,
    payment: CallerReservationPaymentProjection,
    receipt: ChioReceipt,
    execution_nonce: SignedExecutionNonce,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CallerReservationPaymentProjection {
    required: bool,
    hold_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reserved_payment_reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    journal: Option<PaymentJournalRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CallerReservationAuthorizationProjection {
    hold_id: String,
    authorized_exposure_units: u64,
    committed_cost_units_after: u64,
    invocation_count_after: u32,
    invocation_counts_after: Vec<CallerReservationQuotaProjection>,
    invocation_state: String,
    monetary_state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    revocation_set: Option<CallerReservationRevocationProjection>,
    authority: Option<BudgetEventAuthority>,
    guarantee_level: String,
    budget_profile: String,
    metering_profile: String,
    budget_commit_index: Option<u64>,
    event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    partition_escrow_evidence: Option<CallerReservationPartitionEscrowProjection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CallerReservationPartitionEscrowProjection {
    canonical_json: String,
    evidence_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CallerReservationQuotaProjection {
    profile: String,
    owner_id: String,
    grant_index: Option<u32>,
    max_invocations: u32,
    reserved_invocations_after: u32,
    captured_invocations_after: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CallerReservationRevocationProjection {
    ids: Vec<String>,
    digest: String,
}

impl CallerReservationAuthorizationProjection {
    fn from_authorized(authorized: &AuthorizedBudgetHold) -> Result<Self, KernelError> {
        let hold_id = authorized.hold_id.clone().ok_or_else(|| {
            KernelError::Internal(
                "caller reservation authorization omitted its exact hold id".to_string(),
            )
        })?;
        let invocation_counts_after = authorized
            .invocation_counts_after
            .iter()
            .map(|usage| CallerReservationQuotaProjection {
                profile: usage.quota.key().profile().as_str().to_string(),
                owner_id: usage.quota.key().owner_id().to_string(),
                grant_index: usage.quota.key().grant_index(),
                max_invocations: usage.quota.max_invocations(),
                reserved_invocations_after: usage.reserved_invocations_after,
                captured_invocations_after: usage.captured_invocations_after,
            })
            .collect();
        let partition_escrow_evidence =
            authorized
                .metadata
                .partition_escrow_evidence
                .as_ref()
                .map(|evidence| CallerReservationPartitionEscrowProjection {
                    canonical_json: evidence.canonical_json().to_string(),
                    evidence_digest: evidence.evidence_digest().to_string(),
                });
        if (authorized.metadata.guarantee_level == BudgetGuaranteeLevel::PartitionEscrowed)
            != partition_escrow_evidence.is_some()
        {
            return Err(KernelError::Internal(
                "caller reservation authorization has inconsistent partition escrow evidence"
                    .to_string(),
            ));
        }
        Ok(Self {
            hold_id,
            authorized_exposure_units: authorized.authorized_exposure_units,
            committed_cost_units_after: authorized.committed_cost_units_after,
            invocation_count_after: authorized.invocation_count_after,
            invocation_counts_after,
            invocation_state: authorized.invocation_state.as_str().to_string(),
            monetary_state: authorized.monetary_state.as_str().to_string(),
            revocation_set: authorized.revocation_set.as_ref().map(|set| {
                CallerReservationRevocationProjection {
                    ids: set.ids().to_vec(),
                    digest: set.digest().to_string(),
                }
            }),
            authority: authorized.metadata.authority.clone(),
            guarantee_level: authorized.metadata.guarantee_level.as_str().to_string(),
            budget_profile: authorized.metadata.budget_profile.as_str().to_string(),
            metering_profile: authorized.metadata.metering_profile.as_str().to_string(),
            budget_commit_index: authorized.metadata.budget_commit_index,
            event_id: authorized.metadata.event_id.clone(),
            partition_escrow_evidence,
        })
    }

    fn to_authorized(&self) -> Result<AuthorizedBudgetHold, KernelError> {
        let mut invocation_counts_after = Vec::with_capacity(self.invocation_counts_after.len());
        for projected in &self.invocation_counts_after {
            let profile = BudgetQuotaProfile::parse(&projected.profile).ok_or_else(|| {
                KernelError::Internal(
                    "caller reservation handoff has an unknown quota profile".to_string(),
                )
            })?;
            let key = BudgetQuotaKey::from_persisted_parts(
                profile,
                projected.owner_id.clone(),
                projected.grant_index,
            )?;
            let usage = BudgetInvocationQuotaUsage {
                quota: BudgetInvocationQuota::from_persisted_parts(key, projected.max_invocations)?,
                reserved_invocations_after: projected.reserved_invocations_after,
                captured_invocations_after: projected.captured_invocations_after,
            };
            usage.validate()?;
            invocation_counts_after.push(usage);
        }
        let invocation_state = BudgetInvocationReservationState::parse(&self.invocation_state)
            .ok_or_else(|| {
                KernelError::Internal(
                    "caller reservation handoff has an unknown invocation state".to_string(),
                )
            })?;
        let monetary_state =
            BudgetMonetaryHoldState::parse(&self.monetary_state).ok_or_else(|| {
                KernelError::Internal(
                    "caller reservation handoff has an unknown monetary state".to_string(),
                )
            })?;
        let guarantee_level = match self.guarantee_level.as_str() {
            "single_node_atomic" => BudgetGuaranteeLevel::SingleNodeAtomic,
            "ha_linearizable" => BudgetGuaranteeLevel::HaLinearizable,
            "partition_escrowed" => BudgetGuaranteeLevel::PartitionEscrowed,
            "advisory_posthoc" => BudgetGuaranteeLevel::AdvisoryPosthoc,
            _ => {
                return Err(KernelError::Internal(
                    "caller reservation handoff has an unknown guarantee level".to_string(),
                ))
            }
        };
        let partition_escrow_evidence = self
            .partition_escrow_evidence
            .as_ref()
            .map(|evidence| {
                PartitionEscrowCommitEvidence::from_canonical_json(
                    evidence.canonical_json.clone(),
                    evidence.evidence_digest.clone(),
                )
            })
            .transpose()?;
        if (guarantee_level == BudgetGuaranteeLevel::PartitionEscrowed)
            != partition_escrow_evidence.is_some()
        {
            return Err(KernelError::Internal(
                "caller reservation handoff has inconsistent partition escrow evidence".to_string(),
            ));
        }
        if self.budget_profile != BudgetAuthorityProfile::AuthoritativeHoldEvent.as_str()
            || self.metering_profile
                != BudgetMeteringProfile::MaxCostPreauthorizeThenReconcileActual.as_str()
        {
            return Err(KernelError::Internal(
                "caller reservation handoff has an unsupported budget profile".to_string(),
            ));
        }
        let revocation_set = self
            .revocation_set
            .as_ref()
            .map(|set| {
                crate::supplemental_quota::CanonicalRevocationSet::from_persisted_parts(
                    set.ids.clone(),
                    set.digest.clone(),
                )
            })
            .transpose()
            .map_err(|error| KernelError::Internal(error.to_string()))?;
        Ok(AuthorizedBudgetHold {
            hold_id: Some(self.hold_id.clone()),
            authorized_exposure_units: self.authorized_exposure_units,
            committed_cost_units_after: self.committed_cost_units_after,
            invocation_count_after: self.invocation_count_after,
            invocation_counts_after,
            invocation_state,
            monetary_state,
            revocation_set,
            metadata: BudgetCommitMetadata {
                authority: self.authority.clone(),
                guarantee_level,
                budget_profile: BudgetAuthorityProfile::AuthoritativeHoldEvent,
                metering_profile: BudgetMeteringProfile::MaxCostPreauthorizeThenReconcileActual,
                budget_commit_index: self.budget_commit_index,
                event_id: self.event_id.clone(),
                partition_escrow_evidence,
            },
        })
    }
}

impl ChioKernel {
    fn caller_reservation_delivery_claim_lease_ms(
        &self,
        federated: bool,
    ) -> Result<u64, KernelError> {
        let append_bound_ms = u64::try_from(
            self.config.deadlines.receipt_append_budget().as_millis(),
        )
        .map_err(|_| {
            KernelError::Internal(
                "caller reservation receipt publication bound exceeds u64 milliseconds".to_string(),
            )
        })?;
        let federation_bound_ms = if federated {
            let cosigner = self.federation_cosigner.as_ref().ok_or_else(|| {
                KernelError::Internal(
                    "caller reservation federation delivery has no cosigner".to_string(),
                )
            })?;
            if !cosigner.supports_complete_receipt_cosigning_profile()
                || !cosigner.supports_idempotent_receipt_cosigning()
            {
                return Err(KernelError::Internal(
                    "caller reservation federation cosigner lacks the complete exact-retry artifact profile"
                        .to_string(),
                ));
            }
            u64::try_from(
                cosigner
                    .maximum_receipt_cosigning_duration()
                    .ok_or_else(|| {
                        KernelError::Internal(
                            "caller reservation federation cosigner has no wall-clock bound"
                                .to_string(),
                        )
                    })?
                    .as_millis(),
            )
            .map_err(|_| {
                KernelError::Internal(
                    "caller reservation federation bound exceeds u64 milliseconds".to_string(),
                )
            })?
        } else {
            0
        };
        append_bound_ms
            .checked_add(federation_bound_ms)
            .and_then(|bound| bound.checked_add(5_000))
            .map(|bound| bound.max(CALLER_RESERVATION_DELIVERY_CLAIM_LEASE_MS))
            .ok_or_else(|| {
                KernelError::Internal(
                    "caller reservation delivery wall-clock bound overflowed u64".to_string(),
                )
            })
    }

    pub(super) fn ensure_caller_reservation_handoff_replay_read_ready(
        &self,
        request: &ToolCallRequest,
    ) -> Result<(), KernelError> {
        let operation_store = self.admission_operation_store.as_ref().ok_or_else(|| {
            KernelError::Internal(
                "caller reservation requires a durable admission operation store".to_string(),
            )
        })?;
        if !operation_store
            .authority_profile()
            .supports_dispatch_workers(self.dispatch_worker_count)
        {
            return Err(KernelError::Internal(
                "caller reservation admission store is not durable for the configured worker topology"
                    .to_string(),
            ));
        }
        let receipt_store = self.receipt_store.as_ref().ok_or_else(|| {
            KernelError::Internal(
                "caller reservation requires a durable authoritative receipt store".to_string(),
            )
        })?;
        if !receipt_store.supports_authoritative_chio_receipt_lookup()
            || receipt_store.durable_storage_identity()?.is_none()
            || receipt_store.writer_serving_closed()
        {
            return Err(KernelError::Internal(
                "caller reservation receipt publication is not durably recoverable".to_string(),
            ));
        }
        if self.settlement_observer.is_some()
            && !receipt_store.supports_durable_settlement_observer_outbox()
        {
            return Err(KernelError::Internal(
                "caller reservation settlement observer lacks atomic durable publication"
                    .to_string(),
            ));
        }
        if request.federated_origin_kernel_id.is_none() {
            return Ok(());
        }
        if !self
            .federation_artifact_store
            .as_ref()
            .is_some_and(|store| store.is_durable())
        {
            return Err(KernelError::Internal(
                "federated caller reservation requires a durable artifact store".to_string(),
            ));
        }
        Ok(())
    }

    pub(super) fn ensure_caller_reservation_handoff_publication_ready(
        &self,
        request: &ToolCallRequest,
    ) -> Result<(), KernelError> {
        self.ensure_caller_reservation_handoff_replay_read_ready(request)?;
        if request.federated_origin_kernel_id.is_none() {
            let _ = self.caller_reservation_delivery_claim_lease_ms(false)?;
            return Ok(());
        }
        if !self
            .federation_artifact_store
            .as_ref()
            .is_some_and(|store| store.supports_atomic_insert_or_equal())
        {
            return Err(KernelError::Internal(
                "federated caller reservation artifact store lacks atomic insert-or-equal"
                    .to_string(),
            ));
        }
        let _ = self.caller_reservation_delivery_claim_lease_ms(true)?;
        Ok(())
    }

    pub(super) fn prepare_caller_reservation_handoff_intent(
        &self,
        preparing: PrepareCallerReservationHandoff<'_>,
    ) -> Result<(), KernelError> {
        let PrepareCallerReservationHandoff {
            request,
            timestamp,
            matched_grant_index,
            admission,
            response_metadata,
            caller_receipt_metadata,
            incomplete_reason,
        } = preparing;
        let trusted_tenant_id = self
            .receipt_tenant_id_for_request(Some(&request.request_id))
            .unwrap_or_else(current_scoped_receipt_tenant_id);
        let store = self.admission_operation_store.as_ref().ok_or_else(|| {
            KernelError::Internal("durable admission operation store is unavailable".to_string())
        })?;
        let operation = store.load(admission.operation_id())?.ok_or_else(|| {
            KernelError::Internal(
                "caller reservation operation disappeared before handoff intent".to_string(),
            )
        })?;
        if operation.kind() != AdmissionOperationKind::ToolDispatch
            || operation.dispatch_state() != AdmissionDispatchState::NotStarted
            || operation.budget_hold_id() != Some(admission.hold_id.as_str())
        {
            return Err(KernelError::Internal(format!(
                "caller reservation handoff intent refused operation {} in {}",
                operation.operation_id(),
                operation.state().as_str()
            )));
        }
        let existing = store
            .load_cleanup_actions(operation.operation_id())?
            .into_iter()
            .find(|action| {
                action.kind() == AdmissionCleanupActionKind::CallerReservationHandoffIntent
            });
        if let Some(existing) = existing {
            let intent = parse_handoff_intent(&existing)?;
            self.validate_handoff_intent(
                &operation,
                &intent,
                Some(request),
                caller_receipt_metadata,
                true,
                timestamp,
            )?;
            return Ok(());
        }
        if !matches!(
            operation.state(),
            AdmissionOperationState::BudgetAuthorized
                | AdmissionOperationState::DelegatedBudgetReserved
                | AdmissionOperationState::ReadyToDispatch
        ) {
            return Err(KernelError::Internal(format!(
                "caller reservation handoff intent cannot first commit in {}",
                operation.state().as_str()
            )));
        }

        let receipt_content = receipt_content_for_output(None, None)?;
        let action =
            ToolCallAction::from_parameters(request.arguments.clone()).map_err(|error| {
                KernelError::ReceiptSigningFailed(format!(
                    "failed to hash caller reservation parameters: {error}"
                ))
            })?;
        let execution_nonce = self
            .mint_execution_nonce_for_allow_reserving_parameter_hash(
                request,
                &request.capability,
                &action.parameter_hash,
                Some(admission.hold_id.as_str()),
            )?
            .ok_or_else(|| {
                KernelError::Internal(
                    "operation-owned caller reservation requires a minted execution nonce"
                        .to_string(),
                )
            })?;
        let request_metadata = request_receipt_metadata(
            request,
            self.attestation_trust_policy.as_ref(),
            timestamp,
            response_metadata.as_ref(),
        )?;
        let base_receipt_metadata = merge_metadata_objects(
            merge_metadata_objects(receipt_content.metadata, request_metadata),
            merge_metadata_objects(
                response_metadata,
                receipt_attribution_metadata(&request.capability, Some(matched_grant_index)),
            ),
        );
        let request_fingerprint_hash = self.ordinary_request_fingerprint_hash(
            request,
            operation.policy_hash(),
            caller_receipt_metadata,
        )?;
        let request_snapshot_hash = canonical_request_snapshot_hash(request)?;
        let caller_receipt_metadata_hash = canonical_optional_json_hash(caller_receipt_metadata)?;
        let federation_admission = self
            .receipt_federation_admission_for_request(
                &request.request_id,
                request.federated_origin_kernel_id.as_deref(),
            )
            .ok_or_else(|| {
                KernelError::Internal(
                    "caller reservation handoff lost its admission-time federation snapshot"
                        .to_string(),
                )
            })?;
        if federation_admission.remote_kernel_id != request.federated_origin_kernel_id {
            return Err(KernelError::Internal(
                "caller reservation federation snapshot changed its origin binding".to_string(),
            ));
        }
        let signer_identity = self.public_key();
        let protocol_admission_base = self.ordinary_admission_receipt_metadata(
            admission,
            &operation,
            serde_json::Value::Null,
        );
        let body = CallerReservationHandoffIntentBody {
            schema: CALLER_RESERVATION_HANDOFF_INTENT_SCHEMA.to_string(),
            operation_id: operation.operation_id().to_string(),
            request_binding_hash: operation.request_binding_hash().to_string(),
            request_fingerprint_hash,
            request_snapshot_hash,
            request_id: request.request_id.clone(),
            capability_id: request.capability.id.clone(),
            authorization_capability_hash: operation.authorization_capability_hash().to_string(),
            matched_grant_index,
            hold_id: admission.hold_id.clone(),
            policy_hash: operation.policy_hash().to_string(),
            tool_server: request.server_id.clone(),
            tool_name: request.tool_name.clone(),
            agent_id: request.agent_id.clone(),
            capability_subject: request.capability.subject.to_hex(),
            trusted_tenant_id,
            caller_receipt_metadata_hash,
            requires_settled_prepayment: Self::is_governed_mustprepay_request(request),
            federation_admission,
            signer_identity: signer_identity.clone(),
            receipt_id: next_receipt_id("rcpt"),
            content_hash: receipt_content.content_hash,
            timestamp: u64::try_from(execution_nonce.nonce.issued_at).map_err(|_| {
                KernelError::Internal(
                    "caller reservation execution nonce issued_at is negative".to_string(),
                )
            })?,
            expires_at: execution_nonce.expires_at(),
            incomplete_reason: incomplete_reason.to_string(),
            action,
            base_receipt_metadata,
            guard_evidence: current_pre_invocation_guard_evidence(),
            protocol_admission_base,
            authorization: CallerReservationAuthorizationProjection::from_authorized(
                &admission.authorized,
            )?,
            execution_nonce: *execution_nonce,
        };
        let envelope = CallerReservationHandoffIntentSigningEnvelope {
            domain: CALLER_RESERVATION_HANDOFF_INTENT_DOMAIN,
            body: &body,
        };
        let (outcome, _) = chio_core::crypto::sign_canonical_with_backend_for_identity(
            self.authority_signing_backend.as_ref(),
            &signer_identity,
            &envelope,
        )
        .map_err(|error| KernelError::ReceiptSigningFailed(error.to_string()))?;
        if outcome.public_key != signer_identity
            || !signer_identity
                .verify_canonical(&envelope, &outcome.signature)
                .map_err(|error| KernelError::ReceiptSigningFailed(error.to_string()))?
        {
            return Err(KernelError::ReceiptSigningFailed(
                "caller reservation handoff intent signature did not verify".to_string(),
            ));
        }
        let intent = SignedCallerReservationHandoffIntent {
            body,
            signature: outcome.signature,
        };
        let action = AdmissionCleanupAction::pending(
            &operation,
            AdmissionCleanupActionKind::CallerReservationHandoffIntent,
            &intent,
        )?;
        let create_error = match store.create_cleanup_action(action.clone()) {
            Ok(AdmissionCleanupActionCreateOutcome::Created(retained))
            | Ok(AdmissionCleanupActionCreateOutcome::Existing(retained))
                if retained == action =>
            {
                return Ok(())
            }
            Ok(AdmissionCleanupActionCreateOutcome::Created(_))
            | Ok(AdmissionCleanupActionCreateOutcome::Existing(_)) => {
                "caller reservation handoff intent store retained a concurrent action".to_string()
            }
            Err(error) => error.to_string(),
        };
        let current = store.load(operation.operation_id())?.ok_or_else(|| {
            KernelError::Internal(format!(
                "caller reservation intent create failed ({create_error}) and its operation disappeared"
            ))
        })?;
        let retained = exact_handoff_action(
            store.as_ref(),
            current.operation_id(),
            AdmissionCleanupActionKind::CallerReservationHandoffIntent,
        )
        .map_err(|reload_error| {
            KernelError::Internal(format!(
                "caller reservation intent create failed ({create_error}) and exact concurrent recovery failed: {reload_error}"
            ))
        })?;
        let retained = parse_handoff_intent(&retained)?;
        self.validate_handoff_intent(
            &current,
            &retained,
            Some(request),
            caller_receipt_metadata,
            true,
            current_unix_timestamp(),
        )
    }

    pub(super) fn caller_reservation_handoff_nonce(
        &self,
        operation_id: &str,
        request: &ToolCallRequest,
        caller_receipt_metadata: Option<&serde_json::Value>,
        now: u64,
    ) -> Result<SignedExecutionNonce, KernelError> {
        let store = self.admission_operation_store.as_ref().ok_or_else(|| {
            KernelError::Internal("durable admission operation store is unavailable".to_string())
        })?;
        let operation = store.load(operation_id)?.ok_or_else(|| {
            KernelError::Internal(
                "caller reservation operation disappeared before nonce lookup".to_string(),
            )
        })?;
        let action = exact_handoff_action(
            store.as_ref(),
            operation.operation_id(),
            AdmissionCleanupActionKind::CallerReservationHandoffIntent,
        )?;
        let intent = parse_handoff_intent(&action)?;
        self.validate_handoff_intent(
            &operation,
            &intent,
            Some(request),
            caller_receipt_metadata,
            true,
            now,
        )?;
        Ok(intent.body.execution_nonce)
    }

    pub(super) fn commit_caller_reservation_handoff(
        &self,
        capture: CallerReservationCaptureOutcome,
        request: &ToolCallRequest,
        caller_receipt_metadata: Option<&serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        let store = self.admission_operation_store.as_ref().ok_or_else(|| {
            KernelError::Internal("durable admission operation store is unavailable".to_string())
        })?;
        let intent_action = exact_handoff_action(
            store.as_ref(),
            capture.current.operation_id(),
            AdmissionCleanupActionKind::CallerReservationHandoffIntent,
        )?;
        let intent = parse_handoff_intent(&intent_action)?;
        let now = current_unix_timestamp();
        self.validate_handoff_intent(
            &capture.current,
            &intent,
            Some(request),
            caller_receipt_metadata,
            false,
            now,
        )?;
        if i64::try_from(now).unwrap_or(i64::MAX) >= intent.body.expires_at {
            self.terminalize_expired_authoritative_caller_reservation(
                &capture.current,
                i64::try_from(now).unwrap_or(i64::MAX),
            )?;
            return Err(KernelError::GuardDenied(
                "caller reservation capture expired before exact handoff publication".to_string(),
            ));
        }
        self.validate_handoff_intent(
            &capture.current,
            &intent,
            Some(request),
            caller_receipt_metadata,
            true,
            now,
        )?;
        self.commit_validated_caller_reservation_handoff(capture, intent_action, intent)
    }

    fn commit_validated_caller_reservation_handoff(
        &self,
        capture: CallerReservationCaptureOutcome,
        intent_action: AdmissionCleanupAction,
        intent: SignedCallerReservationHandoffIntent,
    ) -> Result<ToolCallResponse, KernelError> {
        let store = self.admission_operation_store.as_ref().ok_or_else(|| {
            KernelError::Internal("durable admission operation store is unavailable".to_string())
        })?;
        let now = current_unix_timestamp();
        self.validate_handoff_intent(&capture.current, &intent, None, None, false, now)?;
        let now_i64 = i64::try_from(now).unwrap_or(i64::MAX);
        if now_i64 >= intent.body.expires_at {
            self.terminalize_expired_authoritative_caller_reservation(&capture.current, now_i64)?;
            return Err(KernelError::GuardDenied(
                "caller reservation capture expired before exact handoff publication".to_string(),
            ));
        }
        self.validate_handoff_intent(&capture.current, &intent, None, None, true, now)?;
        let payment = self.caller_reservation_payment_projection(&capture.current, &intent)?;
        let response = self.build_final_handoff_response(
            &capture.reserved,
            &intent,
            capture.capture_metadata,
            &payment,
        )?;
        let payload = CallerReservationHandoffPayload {
            schema: CALLER_RESERVATION_HANDOFF_SCHEMA.to_string(),
            intent_action_id: intent_action.action_id().to_string(),
            intent_payload_hash: intent_action.payload_hash().to_string(),
            operation_id: capture.reserved.operation_id().to_string(),
            request_binding_hash: capture.reserved.request_binding_hash().to_string(),
            request_fingerprint_hash: intent.body.request_fingerprint_hash.clone(),
            request_id: intent.body.request_id.clone(),
            capability_id: intent.body.capability_id.clone(),
            authorization_capability_hash: intent.body.authorization_capability_hash.clone(),
            matched_grant_index: intent.body.matched_grant_index,
            hold_id: intent.body.hold_id.clone(),
            policy_hash: intent.body.policy_hash.clone(),
            signer_identity: intent.body.signer_identity.clone(),
            tool_server: intent.body.tool_server.clone(),
            tool_name: intent.body.tool_name.clone(),
            trusted_tenant_id: intent.body.trusted_tenant_id.clone(),
            timestamp: intent.body.timestamp,
            expires_at: intent.body.expires_at,
            incomplete_reason: intent.body.incomplete_reason.clone(),
            payment,
            receipt: response.receipt.clone(),
            execution_nonce: response
                .execution_nonce
                .as_deref()
                .cloned()
                .ok_or_else(|| {
                    KernelError::Internal(
                        "caller reservation final response omitted its execution nonce".to_string(),
                    )
                })?,
        };
        let handoff_action = AdmissionCleanupAction::pending(
            &capture.current,
            AdmissionCleanupActionKind::CallerReservationHandoff,
            &payload,
        )?;
        let transition = AdmissionOperationCompareAndSwap {
            operation_id: capture.current.operation_id(),
            expected_version: capture.current.version(),
            coordinator_lease_epoch: capture.current.coordinator_lease_epoch(),
            next_state: AdmissionOperationState::CallerReserved,
            next_dispatch_state: AdmissionDispatchState::Committed,
            next_coordinator_lease_epoch: capture.current.coordinator_lease_epoch(),
            last_error: None,
        };
        let publication_now = current_unix_timestamp();
        let publication_now_i64 = i64::try_from(publication_now).unwrap_or(i64::MAX);
        if publication_now_i64 >= intent.body.expires_at {
            self.terminalize_expired_authoritative_caller_reservation(
                &capture.current,
                publication_now_i64,
            )?;
            return Err(KernelError::GuardDenied(
                "caller reservation capture expired before exact handoff publication".to_string(),
            ));
        }
        match store.compare_and_swap_with_cleanup_action(transition, handoff_action.clone())? {
            AdmissionOperationCasOutcome::Applied(applied)
                if same_caller_reserved_projection(&applied, &capture.reserved) =>
            {
                let response = self.finalize_caller_reservation_handoff_delivery(
                    &applied,
                    &intent_action,
                    &handoff_action,
                    current_unix_timestamp(),
                )?;
                Ok(response)
            }
            AdmissionOperationCasOutcome::Conflict(observed)
                if same_caller_reserved_projection(&observed, &capture.reserved) =>
            {
                let retained = exact_handoff_action(
                    store.as_ref(),
                    observed.operation_id(),
                    AdmissionCleanupActionKind::CallerReservationHandoff,
                )?;
                self.finalize_caller_reservation_handoff_delivery(
                    &observed,
                    &intent_action,
                    &retained,
                    current_unix_timestamp(),
                )
            }
            AdmissionOperationCasOutcome::Missing => Err(KernelError::Internal(
                "caller reservation operation disappeared during final handoff".to_string(),
            )),
            AdmissionOperationCasOutcome::Applied(observed)
            | AdmissionOperationCasOutcome::Conflict(observed) => {
                Err(KernelError::Internal(format!(
                    "caller reservation handoff observed incompatible state {}",
                    observed.state().as_str()
                )))
            }
        }
    }

    /// Probe an already-authorized operation before policy evaluation or any
    /// budget/payment mutation. A request-id collision is `Conflict`; only a
    /// fully authenticated exact request can receive a replayed response.
    pub(super) fn probe_caller_reservation_handoff_after_authentication(
        &self,
        request: &ToolCallRequest,
        caller_receipt_metadata: Option<&serde_json::Value>,
    ) -> Result<CallerReservationReplayProbe, KernelError> {
        let now = current_unix_timestamp();
        let _known_tenant_scope = self
            .receipt_tenant_id_for_request(Some(&request.request_id))
            .is_none()
            .then(|| self.scope_receipt_tenant_id_for_request(&request.request_id, None));
        let Some(store) = self.admission_operation_store.as_ref() else {
            return Ok(CallerReservationReplayProbe::Absent);
        };
        let candidates = store.load_by_request_id(
            AdmissionOperationKind::ToolDispatch,
            &request.request_id,
            MAX_CALLER_RESERVATION_REQUEST_CANDIDATES,
        )?;
        let [operation] = candidates.as_slice() else {
            return Ok(if candidates.is_empty() {
                CallerReservationReplayProbe::Absent
            } else {
                CallerReservationReplayProbe::Conflict
            });
        };
        match operation.state() {
            AdmissionOperationState::CallerReserved => {
                let intent_action = exact_handoff_action(
                    store.as_ref(),
                    operation.operation_id(),
                    AdmissionCleanupActionKind::CallerReservationHandoffIntent,
                )?;
                let intent = parse_handoff_intent(&intent_action)?;
                match self.validate_handoff_intent(
                    operation,
                    &intent,
                    Some(request),
                    caller_receipt_metadata,
                    false,
                    now,
                ) {
                    Ok(()) => {}
                    Err(KernelError::GuardDenied(_)) => {
                        return Ok(CallerReservationReplayProbe::Conflict)
                    }
                    Err(error) => return Err(error),
                }
                let action = exact_handoff_action(
                    store.as_ref(),
                    operation.operation_id(),
                    AdmissionCleanupActionKind::CallerReservationHandoff,
                )?;
                let payload = parse_handoff_payload(&action)?;
                let now = i64::try_from(now).unwrap_or(i64::MAX);
                if now >= payload.expires_at {
                    let _ = self.reap_expired_reserved_budget_holds(now)?;
                    return Ok(CallerReservationReplayProbe::Conflict);
                }
                if !self.caller_reservation_handoff_hold_is_live(operation, &intent, &payload)? {
                    return Ok(CallerReservationReplayProbe::Conflict);
                }
                let response = match self.finalize_caller_reservation_handoff_delivery(
                    operation,
                    &intent_action,
                    &action,
                    now as u64,
                ) {
                    Ok(response) => response,
                    Err(KernelError::GuardDenied(_)) => {
                        return Ok(CallerReservationReplayProbe::Conflict)
                    }
                    Err(error) => return Err(error),
                };
                Ok(CallerReservationReplayProbe::Replayed(response))
            }
            AdmissionOperationState::CallerReservationCapturePending => self
                .recover_caller_reservation_handoff_for_probe(
                    operation,
                    request,
                    caller_receipt_metadata,
                    now,
                ),
            _ => Ok(CallerReservationReplayProbe::Conflict),
        }
    }

    pub(super) fn recover_caller_reservation_capture_pending_handoff(
        &self,
        operation_store: &dyn AdmissionOperationStore,
        budget_store: &dyn BudgetStore,
        approval_store: Option<&dyn ApprovalStore>,
        operation: &AdmissionOperation,
    ) -> Result<(), KernelError> {
        if operation.kind() != AdmissionOperationKind::ToolDispatch
            || operation.state() != AdmissionOperationState::CallerReservationCapturePending
            || operation.dispatch_state() != AdmissionDispatchState::NotStarted
        {
            return Err(KernelError::Internal(format!(
                "caller reservation capture recovery refused operation {} in {}",
                operation.operation_id(),
                operation.state().as_str()
            )));
        }
        let intent_action = exact_handoff_action(
            operation_store,
            operation.operation_id(),
            AdmissionCleanupActionKind::CallerReservationHandoffIntent,
        )?;
        let intent = parse_handoff_intent(&intent_action)?;
        self.validate_handoff_intent(
            operation,
            &intent,
            None,
            None,
            false,
            current_unix_timestamp(),
        )?;
        let snapshot = self.load_recovery_budget_snapshot(operation_store, operation)?;
        let authorization_request = snapshot.authorization_request()?;
        let authorized = intent.body.authorization.to_authorized()?;
        self.validate_budget_authorization_decision_for_store(
            budget_store,
            &authorization_request,
            &crate::budget_store::BudgetAuthorizeHoldDecision::Authorized(authorized.clone()),
            &snapshot.authorization_artifact_digests(),
            "caller reservation recovery authorization snapshot",
        )?;
        let expected_authorize_event =
            authorization_request.event_id.as_deref().ok_or_else(|| {
                KernelError::Internal(
                    "caller reservation recovery authorization omitted its event identifier"
                        .to_string(),
                )
            })?;
        let expected_revocation_set = authorization_request.revocation_set().cloned();
        let expected_monetary_state = if authorization_request.requested_exposure_units > 0
            || authorization_request.max_cost_per_invocation.is_some()
            || authorization_request.max_total_cost_units.is_some()
        {
            BudgetMonetaryHoldState::Exposed
        } else {
            BudgetMonetaryHoldState::None
        };
        self.validate_hard_budget_commit_metadata_for_store(
            budget_store,
            &authorized.metadata,
            expected_authorize_event,
            authorization_request.authority.as_ref(),
            None,
            "caller reservation recovery authorization snapshot",
        )?;
        if authorized.hold_id.as_deref() != Some(snapshot.hold_id())
            || authorized.hold_id.as_deref() != operation.budget_hold_id()
            || authorized.authorized_exposure_units
                != authorization_request.requested_exposure_units
            || authorized.invocation_state != BudgetInvocationReservationState::Authorized
            || authorized.monetary_state != expected_monetary_state
            || authorized.revocation_set.as_ref() != expected_revocation_set.as_ref()
        {
            return Err(KernelError::Internal(
                "caller reservation recovery authorization changed its signed snapshot".to_string(),
            ));
        }
        let authority =
            if budget_store.budget_guarantee_level() == BudgetGuaranteeLevel::SingleNodeAtomic {
                snapshot.requested_authority().cloned()
            } else {
                authorized.metadata.authority.clone()
            };
        let capture_request = snapshot.capture_request(authority.clone())?;
        let _guard = match self.budget_store_lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let queried = if snapshot.requires_combined_capture() {
            let revocation_set = snapshot.revocation_set()?;
            let request = AdmissionCaptureRequest::new(AdmissionCaptureRequestInput {
                operation_id: operation.operation_id().to_string(),
                budget: capture_request,
                revocation_set: revocation_set.clone(),
                bound_revocation_set_digest: revocation_set.digest().to_string(),
                authorization_artifact_digests: snapshot.authorization_artifact_digests(),
                aggregate_root_capability_id: snapshot
                    .aggregate_root_capability_id()
                    .map(ToOwned::to_owned),
                aggregate_root_binding_digest: snapshot
                    .aggregate_root_binding_digest()
                    .map(ToOwned::to_owned),
                last_observed_revocation_index: None,
            })?;
            let capture_authority = self.admission_capture_authority.as_ref().ok_or_else(|| {
                KernelError::Internal(
                    "combined admission capture authority is unavailable during caller recovery"
                        .to_string(),
                )
            })?;
            match capture_authority.query_admission_capture(&request)? {
                Some(AdmissionCaptureDecision::Captured { budget, metadata }) => {
                    let projection = CombinedAdmissionCaptureReceiptProjection::from_capture(
                        &request,
                        &authorized,
                        &budget,
                        &metadata,
                    )?;
                    Some((
                        *budget,
                        serde_json::to_value(projection).map_err(|error| {
                            KernelError::Internal(format!(
                                "caller reservation combined capture projection failed: {error}"
                            ))
                        })?,
                    ))
                }
                Some(AdmissionCaptureDecision::Denied(denial)) => {
                    super::ordinary_admission::validate_capture_denial_partition_escrow_evidence(
                        &authorized,
                        &denial,
                        "caller reservation recovery capture denial",
                    )?;
                    None
                }
                None => None,
            }
        } else {
            budget_store
                .query_invocation_capture(&capture_request)?
                .map(|captured| {
                    let projection = BudgetInvocationCaptureReceiptProjection::from_capture(
                        operation.operation_id(),
                        &authorized,
                        &captured,
                    )?;
                    let projection = serde_json::to_value(projection).map_err(|error| {
                        KernelError::Internal(format!(
                            "caller reservation capture projection failed: {error}"
                        ))
                    })?;
                    Ok::<_, KernelError>((captured, projection))
                })
                .transpose()?
        };
        let Some((captured, capture_metadata)) = queried else {
            drop(_guard);
            return self.compensate_recovery_capture_denial(
                operation_store,
                budget_store,
                approval_store,
                operation,
                "caller reservation recovery proved capture was never committed",
            );
        };
        self.validate_hard_budget_commit_metadata_for_store(
            budget_store,
            &captured.metadata,
            snapshot.capture_event_id(),
            authority.as_ref(),
            authorized.metadata.budget_commit_index,
            "caller reservation recovery invocation capture",
        )?;
        if captured.hold_id.as_deref() != Some(snapshot.hold_id())
            || captured.exposure_units != authorized.authorized_exposure_units
            || captured.realized_spend_units != 0
            || captured.invocation_state != BudgetInvocationReservationState::Captured
            || captured.monetary_state != expected_monetary_state
            || captured.revocation_set.as_ref() != expected_revocation_set.as_ref()
        {
            return Err(KernelError::Internal(
                "caller reservation recovered capture changed its immutable effect".to_string(),
            ));
        }
        self.validate_caller_reservation_replay_reservations(approval_store, operation)?;
        drop(_guard);
        let reserved = operation.transition_checked(
            AdmissionOperationState::CallerReserved,
            AdmissionDispatchState::Committed,
            operation.coordinator_lease_epoch(),
            None,
        )?;
        let result = self.commit_validated_caller_reservation_handoff(
            CallerReservationCaptureOutcome {
                current: operation.clone(),
                reserved,
                capture_metadata,
            },
            intent_action,
            intent,
        );
        match result {
            Ok(_) => Ok(()),
            Err(error @ KernelError::GuardDenied(_)) => {
                let terminalized =
                    operation_store
                        .load(operation.operation_id())?
                        .is_some_and(|current| {
                            current.state() == AdmissionOperationState::OutcomeUnknownAfterDispatch
                        });
                if terminalized {
                    Ok(())
                } else {
                    Err(error)
                }
            }
            Err(error) => Err(error),
        }
    }

    pub(super) fn validated_caller_reservation_reap_expiry(
        &self,
        operation_store: &dyn AdmissionOperationStore,
        operation: &AdmissionOperation,
    ) -> Result<i64, KernelError> {
        if operation.kind() != AdmissionOperationKind::ToolDispatch
            || !matches!(
                (operation.state(), operation.dispatch_state()),
                (
                    AdmissionOperationState::CallerReserved,
                    AdmissionDispatchState::Committed
                ) | (
                    AdmissionOperationState::CallerReservationCapturePending,
                    AdmissionDispatchState::NotStarted
                )
            )
        {
            return Err(KernelError::Internal(
                "caller reservation reap candidate is not in an expirable state".to_string(),
            ));
        }
        let intent_action = exact_handoff_action(
            operation_store,
            operation.operation_id(),
            AdmissionCleanupActionKind::CallerReservationHandoffIntent,
        )?;
        let intent = parse_handoff_intent(&intent_action)?;
        self.validate_handoff_intent(operation, &intent, None, None, false, 0)?;
        Ok(intent.body.expires_at)
    }

    pub(super) fn validate_caller_reservation_capture_pending_for_reap(
        &self,
        operation_store: &dyn AdmissionOperationStore,
        operation: &AdmissionOperation,
    ) -> Result<(), KernelError> {
        if operation.kind() != AdmissionOperationKind::ToolDispatch
            || operation.state() != AdmissionOperationState::CallerReservationCapturePending
            || operation.dispatch_state() != AdmissionDispatchState::NotStarted
        {
            return Err(KernelError::Internal(
                "caller reservation reap candidate is not capture-pending".to_string(),
            ));
        }
        let _ = self.validated_caller_reservation_reap_expiry(operation_store, operation)?;
        let intent_action = exact_handoff_action(
            operation_store,
            operation.operation_id(),
            AdmissionCleanupActionKind::CallerReservationHandoffIntent,
        )?;
        let intent = parse_handoff_intent(&intent_action)?;
        let snapshot = self.load_recovery_budget_snapshot(operation_store, operation)?;
        if snapshot.hold_id() != intent.body.hold_id {
            return Err(KernelError::Internal(
                "caller reservation reap candidate changed its signed hold".to_string(),
            ));
        }
        Ok(())
    }

    fn validate_caller_reservation_replay_reservations(
        &self,
        approval_store: Option<&dyn ApprovalStore>,
        operation: &AdmissionOperation,
    ) -> Result<(), KernelError> {
        if let Some(expected_hash) = operation.approval_set_hash() {
            let reservation = approval_store
                .ok_or_else(|| {
                    KernelError::Internal(
                        "caller reservation approval authority is unavailable during recovery"
                            .to_string(),
                    )
                })?
                .get_approval_reservation(operation.operation_id())
                .map_err(|error| KernelError::Internal(error.to_string()))?
                .ok_or_else(|| {
                    KernelError::Internal(
                        "caller reservation capture has no approval reservation".to_string(),
                    )
                })?;
            if reservation.state() != ReplayReservationState::Committed
                || reservation.approval_set().approval_set_hash() != expected_hash
            {
                return Err(KernelError::Internal(
                    "caller reservation capture has no exact committed approval".to_string(),
                ));
            }
        }
        if let Some(expected_nonce_id) = operation.execution_nonce_id() {
            let reservation = self
                .execution_nonce_store
                .as_deref()
                .ok_or_else(|| {
                    KernelError::Internal(
                        "caller reservation nonce authority is unavailable during recovery"
                            .to_string(),
                    )
                })?
                .get_nonce_reservation(operation.operation_id())
                .map_err(|error| KernelError::Internal(error.to_string()))?
                .ok_or_else(|| {
                    KernelError::Internal(
                        "caller reservation capture has no execution nonce reservation".to_string(),
                    )
                })?;
            if reservation.state() != ReplayReservationState::Committed
                || reservation.nonce_id() != expected_nonce_id
            {
                return Err(KernelError::Internal(
                    "caller reservation capture has no exact committed execution nonce".to_string(),
                ));
            }
        }
        Ok(())
    }
}

include!("caller_reservation_handoff.part2.inc");

fn parse_handoff_intent(
    action: &AdmissionCleanupAction,
) -> Result<SignedCallerReservationHandoffIntent, KernelError> {
    if action.kind() != AdmissionCleanupActionKind::CallerReservationHandoffIntent {
        return Err(KernelError::Internal(
            "caller reservation intent lookup returned the wrong action kind".to_string(),
        ));
    }
    serde_json::from_str(action.payload_json()).map_err(|error| {
        KernelError::Internal(format!(
            "caller reservation handoff intent payload is invalid: {error}"
        ))
    })
}

fn parse_handoff_payload(
    action: &AdmissionCleanupAction,
) -> Result<CallerReservationHandoffPayload, KernelError> {
    if action.kind() != AdmissionCleanupActionKind::CallerReservationHandoff {
        return Err(KernelError::Internal(
            "caller reservation handoff lookup returned the wrong action kind".to_string(),
        ));
    }
    serde_json::from_str(action.payload_json()).map_err(|error| {
        KernelError::Internal(format!(
            "caller reservation final handoff payload is invalid: {error}"
        ))
    })
}

fn exact_handoff_action(
    store: &dyn crate::admission_operation::AdmissionOperationStore,
    operation_id: &str,
    kind: AdmissionCleanupActionKind,
) -> Result<AdmissionCleanupAction, KernelError> {
    let actions = store
        .load_cleanup_actions(operation_id)?
        .into_iter()
        .filter(|action| action.kind() == kind)
        .collect::<Vec<_>>();
    let [action] = actions.as_slice() else {
        return Err(KernelError::Internal(format!(
            "caller reservation operation must retain exactly one {} action",
            kind.as_str()
        )));
    };
    Ok(action.clone())
}

fn canonical_optional_json_hash(value: Option<&serde_json::Value>) -> Result<String, KernelError> {
    let tagged = serde_json::json!({
        "present": value.is_some(),
        "value": value,
    });
    chio_core::canonical::canonical_json_bytes(&tagged)
        .map(|bytes| chio_core::crypto::sha256_hex(&bytes))
        .map_err(|error| KernelError::Internal(error.to_string()))
}

fn canonical_request_snapshot_hash(request: &ToolCallRequest) -> Result<String, KernelError> {
    let canonical = chio_core::canonical::canonical_json_bytes(request)
        .map_err(|error| KernelError::GuardDenied(error.to_string()))?;
    let mut bound =
        Vec::with_capacity(CALLER_RESERVATION_HANDOFF_INTENT_DOMAIN.len() + canonical.len());
    bound.extend_from_slice(CALLER_RESERVATION_HANDOFF_INTENT_DOMAIN.as_bytes());
    bound.extend_from_slice(&canonical);
    Ok(chio_core::crypto::sha256_hex(&bound))
}

fn finalize_protocol_admission_metadata(
    mut base: serde_json::Value,
    capture: serde_json::Value,
    reserved: &AdmissionOperation,
) -> Result<serde_json::Value, KernelError> {
    let protocol = base
        .as_object_mut()
        .and_then(|root| root.get_mut("protocol_admission"))
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| {
            KernelError::Internal(
                "caller reservation handoff omitted protocol admission metadata".to_string(),
            )
        })?;
    protocol.insert("invocation_capture".to_string(), capture);
    protocol.insert(
        "admission_operation".to_string(),
        serde_json::json!({
            "operation_id": reserved.operation_id(),
            "state": reserved.state().as_str(),
            "dispatch_state": reserved.dispatch_state().as_str(),
            "version": reserved.version(),
        }),
    );
    Ok(base)
}

fn same_caller_reserved_projection(
    observed: &AdmissionOperation,
    expected: &AdmissionOperation,
) -> bool {
    observed.operation_id() == expected.operation_id()
        && observed.request_binding_hash() == expected.request_binding_hash()
        && observed.state() == AdmissionOperationState::CallerReserved
        && observed.dispatch_state() == AdmissionDispatchState::Committed
        && observed.version() == expected.version()
        && observed.coordinator_lease_epoch() == expected.coordinator_lease_epoch()
}

fn validate_final_handoff_payload(
    current_signer: &chio_core::crypto::PublicKey,
    operation: &AdmissionOperation,
    intent_action: &AdmissionCleanupAction,
    intent: &SignedCallerReservationHandoffIntent,
    payload: &CallerReservationHandoffPayload,
    now: u64,
    require_unexpired: bool,
) -> Result<(), KernelError> {
    let body = &intent.body;
    let receipt = &payload.receipt;
    let expected_coordinator_authority_id = format!("kernel:{}", current_signer.to_hex());
    let action_matches = receipt.action.parameter_hash == body.action.parameter_hash
        && receipt.action.parameters == body.action.parameters;
    let decision_matches = matches!(
        receipt.decision.as_ref(),
        Some(Decision::Incomplete { reason }) if reason == &body.incomplete_reason
    );
    let receipt_signing_nonce_matches = receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("chio_receipt_signing_nonce"))
        .and_then(serde_json::Value::as_str)
        == Some(body.receipt_id.as_str());
    let now = i64::try_from(now).unwrap_or(i64::MAX);
    if payload.schema != CALLER_RESERVATION_HANDOFF_SCHEMA
        || intent_action.kind() != AdmissionCleanupActionKind::CallerReservationHandoffIntent
        || intent_action.operation_id() != operation.operation_id()
        || intent_action.request_binding_hash() != operation.request_binding_hash()
        || payload.intent_action_id != intent_action.action_id()
        || payload.intent_payload_hash != intent_action.payload_hash()
        || operation.kind() != AdmissionOperationKind::ToolDispatch
        || operation.state() != AdmissionOperationState::CallerReserved
        || operation.dispatch_state() != AdmissionDispatchState::Committed
        || operation.coordinator_authority_id() != expected_coordinator_authority_id
        || body.signer_identity != *current_signer
        || payload.signer_identity != *current_signer
        || payload.operation_id != operation.operation_id()
        || payload.operation_id != body.operation_id
        || payload.request_binding_hash != operation.request_binding_hash()
        || payload.request_binding_hash != body.request_binding_hash
        || payload.request_fingerprint_hash != body.request_fingerprint_hash
        || payload.request_id != operation.request_id()
        || payload.request_id != body.request_id
        || payload.capability_id != operation.capability_id()
        || payload.capability_id != body.capability_id
        || payload.authorization_capability_hash != operation.authorization_capability_hash()
        || payload.authorization_capability_hash != body.authorization_capability_hash
        || payload.matched_grant_index != body.matched_grant_index
        || payload.hold_id.as_str() != operation.budget_hold_id().unwrap_or_default()
        || payload.hold_id != body.hold_id
        || payload.policy_hash != operation.policy_hash()
        || payload.policy_hash != body.policy_hash
        || payload.tool_server != body.tool_server
        || payload.tool_name != body.tool_name
        || payload.trusted_tenant_id != body.trusted_tenant_id
        || payload.timestamp != body.timestamp
        || payload.expires_at != body.expires_at
        || payload.incomplete_reason != body.incomplete_reason
        || payload.execution_nonce != body.execution_nonce
        || payload.payment.required != body.requires_settled_prepayment
        || payload.payment.hold_id != body.hold_id
        || payload.expires_at != payload.execution_nonce.expires_at()
        || (require_unexpired && now >= payload.expires_at)
        || payload.execution_nonce.reserved_hold_id() != Some(payload.hold_id.as_str())
        || payload.execution_nonce.reserving_request_id() != Some(payload.request_id.as_str())
        || !receipt_signing_nonce_matches
        || receipt.timestamp != body.timestamp
        || receipt.capability_id != body.capability_id
        || receipt.tool_server != body.tool_server
        || receipt.tool_name != body.tool_name
        || !action_matches
        || !decision_matches
        || receipt.receipt_kind != chio_core::receipt::kinds::ReceiptKind::MediatedDecision
        || receipt.boundary_class != chio_core::receipt::kinds::BoundaryClass::Prevent
        || receipt.observation_outcome.is_some()
        || receipt.tool_origin != chio_core::receipt::kinds::ToolOrigin::CallerExecuted
        || receipt.redaction_mode != chio_core::receipt::kinds::RedactionMode::None
        || !receipt.actor_chain.is_empty()
        || receipt.content_hash != body.content_hash
        || receipt.policy_hash != body.policy_hash
        || receipt.trust_level != chio_core::receipt::kinds::TrustLevel::Mediated
        || receipt.tenant_id != body.trusted_tenant_id
        || receipt.kernel_key != *current_signer
        || receipt.bbs_projection_version.is_some()
        || receipt.bbs_signature.is_some()
        || receipt.algorithm.unwrap_or_default() != receipt.signature.algorithm()
        || receipt.kernel_key.algorithm() != receipt.signature.algorithm()
        || !receipt.action.verify_hash().map_err(|error| {
            KernelError::Internal(format!("caller reservation receipt action failed: {error}"))
        })?
        || !receipt.verify_signature().map_err(|error| {
            KernelError::Internal(format!(
                "caller reservation receipt verification failed: {error}"
            ))
        })?
    {
        return Err(KernelError::Internal(
            "caller reservation final handoff failed immutable binding validation".to_string(),
        ));
    }

    let expected_payment_binding = BudgetAdmissionOperationBinding::new(
        operation.operation_id().to_string(),
        operation.request_binding_hash().to_string(),
    )?;
    if payload.payment.required {
        let journal = payload.payment.journal.as_ref().ok_or_else(|| {
            KernelError::Internal(
                "caller reservation final handoff omitted its settled payment journal".to_string(),
            )
        })?;
        let transaction_id = payload
            .payment
            .reserved_payment_reference
            .as_deref()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                KernelError::Internal(
                    "caller reservation final handoff omitted its payment transaction".to_string(),
                )
            })?;
        if journal.state != PaymentJournalState::Settled
            || journal.request_id != body.request_id
            || journal.capability_id != body.capability_id
            || usize::try_from(journal.grant_index).ok() != Some(body.matched_grant_index)
            || journal.admission_operation.as_ref() != Some(&expected_payment_binding)
            || journal.hold_id.as_deref() != Some(body.hold_id.as_str())
            || journal.transaction_id.as_deref() != Some(transaction_id)
            || journal.tenant_id != body.trusted_tenant_id
        {
            return Err(KernelError::Internal(
                "caller reservation final handoff changed its settled payment journal".to_string(),
            ));
        }
    } else if payload.payment.journal.is_some()
        || payload.payment.reserved_payment_reference.is_some()
    {
        return Err(KernelError::Internal(
            "caller reservation final handoff added unexpected payment evidence".to_string(),
        ));
    }

    if !canonical_serialized_values_equal(&receipt.evidence, &body.guard_evidence)? {
        return Err(KernelError::Internal(
            "caller reservation final receipt changed its guard evidence".to_string(),
        ));
    }
    let capture_metadata = receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.pointer("/protocol_admission/invocation_capture"))
        .cloned()
        .ok_or_else(|| {
            KernelError::Internal(
                "caller reservation final receipt omitted invocation capture evidence".to_string(),
            )
        })?;
    let expected_protocol = finalize_protocol_admission_metadata(
        body.protocol_admission_base.clone(),
        capture_metadata,
        operation,
    )?;
    let expected_metadata = merge_metadata_objects(
        merge_metadata_objects(
            merge_metadata_objects(body.base_receipt_metadata.clone(), Some(expected_protocol)),
            Some(serde_json::json!({
                "caller_reservation_payment": &payload.payment,
            })),
        ),
        Some(serde_json::json!({
            "receipt_context": { "request_id": &body.request_id }
        })),
    );
    let expected_metadata = merge_metadata_objects(
        expected_metadata,
        Some(serde_json::json!({
            "chio_receipt_signing_nonce": &body.receipt_id,
        })),
    );
    if receipt.metadata != expected_metadata {
        return Err(KernelError::Internal(
            "caller reservation final receipt changed its frozen metadata".to_string(),
        ));
    }
    crate::kernel::responses::require_earned_mediated_trust_level(
        receipt.metadata.as_ref(),
        chio_core::receipt::kinds::TrustLevel::Mediated,
    )?;
    Ok(())
}

fn canonical_serialized_values_equal<T: Serialize>(
    left: &T,
    right: &T,
) -> Result<bool, KernelError> {
    let left = chio_core::canonical::canonical_json_bytes(left)
        .map_err(|error| KernelError::Internal(error.to_string()))?;
    let right = chio_core::canonical::canonical_json_bytes(right)
        .map_err(|error| KernelError::Internal(error.to_string()))?;
    Ok(left == right)
}

fn validate_caller_reservation_dual_receipt(
    kernel: &ChioKernel,
    peer: &chio_federation::trust_establishment::FederationPeer,
    receipt: &ChioReceipt,
    dual: &chio_federation::bilateral::DualSignedReceipt,
) -> Result<(), KernelError> {
    if !canonical_serialized_values_equal(&dual.body, receipt)? {
        return Err(KernelError::Internal(
            "caller reservation durable dual receipt changed its local receipt".to_string(),
        ));
    }
    let local_kernel_id = kernel.federation_local_kernel_id();
    let local_public_key = kernel.public_key();
    dual.verify_pinned(chio_federation::bilateral::ExpectedBilateralPeers {
        org_a_kernel_id: &peer.kernel_id,
        org_a_public_key: &peer.public_key,
        org_b_kernel_id: &local_kernel_id,
        org_b_public_key: &local_public_key,
    })
    .map_err(|error| {
        KernelError::Internal(format!(
            "caller reservation durable dual receipt is invalid: {error}"
        ))
    })
}

fn validate_caller_reservation_dsse(
    kernel: &ChioKernel,
    peer: &chio_federation::trust_establishment::FederationPeer,
    receipt: &ChioReceipt,
    dsse: &chio_federation::bilateral_dsse::DsseEnvelope,
) -> Result<(), KernelError> {
    let local_public_key = kernel.public_key();
    let statement = chio_federation::bilateral_dsse::verify_chio_bilateral_dsse_envelope(
        dsse,
        &peer.public_key,
        &local_public_key,
    )
    .map_err(|error| {
        KernelError::Internal(format!(
            "caller reservation durable bilateral DSSE is invalid: {error}"
        ))
    })?;
    let receipt_body_digest = chio_core::crypto::sha256_hex(
        &chio_core::canonical::canonical_json_bytes(&receipt.body()).map_err(|error| {
            KernelError::Internal(format!(
                "caller reservation receipt body canonicalization failed: {error}"
            ))
        })?,
    );
    let receipt_digest = chio_core::crypto::sha256_hex(
        &chio_core::canonical::canonical_json_bytes(receipt).map_err(|error| {
            KernelError::Internal(format!(
                "caller reservation receipt canonicalization failed: {error}"
            ))
        })?,
    );
    let local_kernel_id = kernel.federation_local_kernel_id();
    let local_keyid = chio_federation::bilateral_dsse::Keyid::from_public_key(&local_public_key);
    let remote_keyid = chio_federation::bilateral_dsse::Keyid::from_public_key(&peer.public_key);
    let [subject] = statement.subject.as_slice() else {
        return Err(KernelError::Internal(
            "caller reservation durable bilateral DSSE has a noncanonical subject set".to_string(),
        ));
    };
    let predicate = &statement.predicate;
    let tool_args_hash = predicate.tool_args_hash.as_ref().ok_or_else(|| {
        KernelError::Internal(
            "caller reservation durable bilateral DSSE omitted its tool argument hash".to_string(),
        )
    })?;
    let treaty = predicate.treaty_binding_ref.as_ref().ok_or_else(|| {
        KernelError::Internal(
            "caller reservation durable bilateral DSSE omitted its treaty receipt binding"
                .to_string(),
        )
    })?;
    if predicate.invocation_id != receipt.id
        || predicate.tool_name != receipt.tool_name
        || predicate.timestamp_unix_ms != receipt.timestamp.saturating_mul(1_000)
        || predicate.tool_server_a.kernel_id != peer.kernel_id
        || predicate.tool_server_a.passport_key_fingerprint != remote_keyid
        || predicate.tool_server_b.kernel_id != local_kernel_id
        || predicate.tool_server_b.passport_key_fingerprint != local_keyid
        || tool_args_hash.alg != "sha256"
        || tool_args_hash.value != receipt.action.parameter_hash
        || subject.name != chio_federation::bilateral_dsse::receipt_subject_name(&receipt.id)
        || subject.digest.sha256 != receipt_body_digest
        || treaty.request_sha256 != receipt.action.parameter_hash
        || treaty.outcome_sha256 != receipt.content_hash
        || treaty.remote_receipt_sha256 != receipt_digest
        || treaty.signer_kernel_ids != [peer.kernel_id.clone(), local_kernel_id]
    {
        return Err(KernelError::Internal(
            "caller reservation durable bilateral DSSE changed its receipt binding".to_string(),
        ));
    }
    Ok(())
}
