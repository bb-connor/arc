use std::fmt;
use std::sync::Arc;

use serde::Serialize;

use super::*;
use crate::admission_operation::{
    AdmissionAttachment, AdmissionBeginResult, AdmissionDigest, AdmissionIdentifier,
    AdmissionOperationBindingInputV1, AdmissionOperationBindingV1, AdmissionOperationCommand,
    AdmissionOperationKind, AdmissionOperationState, AdmissionOperationV1,
    AdmissionParticipantRequirements, AdmissionRequestBindingV1, AuthenticatedRequestNamespace,
    ProviderAttemptBindingV1, QualifiedAdmissionOperationStore,
    QualifiedAdmissionOperationStoreExt, SideEffectClass, StoreMutationFence,
};
use crate::budget_store::{BudgetAdmissionBinding, BudgetEventAuthority};
use crate::supplemental_quota::CanonicalRevocationSet;

const RECOVERY_LEASE_DURATION_MS: u64 = 60_000;
const I_JSON_MAX_SAFE_INTEGER: u64 = (1_u64 << 53) - 1;

#[derive(Clone)]
pub(crate) struct DurableAdmissionRuntime {
    store: Arc<dyn QualifiedAdmissionOperationStore>,
    fence: StoreMutationFence,
    claimant_id: AdmissionIdentifier,
}

impl fmt::Debug for DurableAdmissionRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableAdmissionRuntime")
            .field("fence", &self.fence)
            .field("claimant_id", &self.claimant_id)
            .finish_non_exhaustive()
    }
}

impl DurableAdmissionRuntime {
    pub(crate) fn new(
        store: Arc<dyn QualifiedAdmissionOperationStore>,
        fence: StoreMutationFence,
        kernel_id: &str,
    ) -> Result<Self, crate::admission_operation::AdmissionOperationError> {
        AdmissionIdentifier::try_new("store_uuid", fence.store_uuid.clone())?;
        AdmissionIdentifier::try_new("store_lease_id", fence.lease_id.clone())?;
        if fence.owner_epoch == 0 || fence.owner_epoch > I_JSON_MAX_SAFE_INTEGER {
            return Err(crate::admission_operation::AdmissionOperationError::InvalidStoreFence);
        }
        let claimant_id =
            AdmissionIdentifier::try_new("admission_claimant_id", format!("kernel:{kernel_id}"))?;
        Ok(Self {
            store,
            fence,
            claimant_id,
        })
    }

    fn authority(&self) -> BudgetEventAuthority {
        BudgetEventAuthority {
            authority_id: self.fence.store_uuid.clone(),
            lease_id: self.fence.lease_id.clone(),
            lease_epoch: self.fence.owner_epoch,
        }
    }
}

pub(crate) struct DurableToolAdmission {
    operation: AdmissionOperationV1,
}

impl DurableToolAdmission {
    pub(crate) fn operation_id(&self) -> &str {
        self.operation.binding().operation_id().as_str()
    }

    pub(crate) fn budget_hold_id(&self, grant_index: usize) -> String {
        format!("admission-budget:{}:{grant_index}", self.operation_id())
    }

    pub(crate) fn budget_authorize_event_id(&self, grant_index: usize) -> String {
        format!("{}:authorize", self.budget_hold_id(grant_index))
    }

    pub(crate) fn permits_grant(&self, grant_index: usize) -> bool {
        self.operation
            .budget_hold_id()
            .is_none_or(|hold_id| hold_id.as_str() == self.budget_hold_id(grant_index))
    }

    pub(crate) fn can_resume_captured_hold(&self) -> bool {
        self.operation.state() == AdmissionOperationState::CapturePending
    }
}

#[derive(Serialize)]
struct ImmutableToolAdmissionRequest<'a> {
    schema: &'static str,
    server_id: &'a str,
    tool_name: &'a str,
    agent_id: &'a str,
    arguments: &'a serde_json::Value,
    governed_intent: &'a Option<chio_core::capability::governance::GovernedTransactionIntent>,
    model_metadata: &'a Option<chio_core::capability::scope::ModelMetadata>,
    federated_origin_kernel_id: &'a Option<String>,
    matching_grants: Vec<ImmutableMatchingGrant<'a>>,
}

#[derive(Serialize)]
struct ImmutableMatchingGrant<'a> {
    index: usize,
    grant: &'a ToolGrant,
}

impl ChioKernel {
    pub(crate) fn begin_durable_tool_admission(
        &self,
        request: &ToolCallRequest,
        matching_grants: &[MatchingGrant<'_>],
        trusted_now_unix_ms: u64,
    ) -> Result<Option<DurableToolAdmission>, KernelError> {
        let effect_class = if matching_grants.iter().any(|matching| {
            matching.grant.max_cost_per_invocation.is_some()
                || matching.grant.max_total_cost.is_some()
        }) {
            SideEffectClass::Monetary
        } else {
            SideEffectClass::SideEffecting
        };
        if !self.durable_admission_mode.covers(effect_class) {
            return Ok(None);
        }
        let Some(runtime) = self.durable_admission_runtime.as_ref() else {
            if self.config.allow_ephemeral_receipt_log {
                return Ok(None);
            }
            return Err(KernelError::DurableAdmission(
                "no qualified admission operation store is configured".to_string(),
            ));
        };

        let immutable_request = ImmutableToolAdmissionRequest {
            schema: "chio.tool-admission-request.v1",
            server_id: &request.server_id,
            tool_name: &request.tool_name,
            agent_id: &request.agent_id,
            arguments: &request.arguments,
            governed_intent: &request.governed_intent,
            model_metadata: &request.model_metadata,
            federated_origin_kernel_id: &request.federated_origin_kernel_id,
            matching_grants: matching_grants
                .iter()
                .map(|matching| ImmutableMatchingGrant {
                    index: matching.index,
                    grant: matching.grant,
                })
                .collect(),
        };
        let immutable_request_hash =
            admission_digest("immutable_request_hash", &immutable_request)?;
        let authorization_capability_hash =
            admission_digest("authorization_capability_hash", &request.capability)?;
        let policy_hash = AdmissionDigest::try_new("policy_hash", self.config.policy_hash.clone())
            .or_else(|_| {
                AdmissionDigest::try_new(
                    "policy_hash",
                    sha256_hex(self.config.policy_hash.as_bytes()),
                )
            })?;
        let requirements = AdmissionParticipantRequirements {
            broker_attempt: true,
            budget_capture: true,
            ..AdmissionParticipantRequirements::NONE
        };
        let namespace =
            AuthenticatedRequestNamespace::for_local_system(AdmissionIdentifier::try_new(
                "coordinator_authority_id",
                runtime.fence.store_uuid.clone(),
            )?)?;
        let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
            kind: AdmissionOperationKind::ToolDispatch,
            namespace,
            request_id: AdmissionIdentifier::try_new("request_id", request.request_id.clone())?,
            capability_id: AdmissionIdentifier::try_new(
                "capability_id",
                request.capability.id.clone(),
            )?,
            authorization_capability_hash,
            request_binding: AdmissionRequestBindingV1::new(immutable_request_hash, requirements)?,
            policy_hash,
            effect_class,
        })?;
        let prepared = AdmissionOperationV1::prepare(binding, runtime.fence.owner_epoch)?;
        let operation = match runtime
            .store
            .begin(&prepared, &runtime.fence, trusted_now_unix_ms)
            .map_err(durable_store_error)?
        {
            AdmissionBeginResult::Created(operation) => operation,
            AdmissionBeginResult::ExactReplay { operation, .. }
                if matches!(
                    operation.state(),
                    AdmissionOperationState::Prepared
                        | AdmissionOperationState::BrokerAttemptRegistered
                        | AdmissionOperationState::BudgetAuthorized
                        | AdmissionOperationState::ReadyToDispatch
                        | AdmissionOperationState::CapturePending
                ) =>
            {
                operation
            }
            AdmissionBeginResult::ExactReplay { operation, .. } => {
                return Err(KernelError::DurableAdmission(format!(
                    "request replay is retained in state {:?}",
                    operation.state()
                )));
            }
            AdmissionBeginResult::Conflict {
                existing_operation_id,
            } => {
                return Err(KernelError::DurableAdmission(format!(
                    "request id conflicts with retained operation {}",
                    existing_operation_id.as_str()
                )));
            }
        };
        let expected_attempt = ProviderAttemptBindingV1 {
            operation_id: operation.binding().operation_id().as_str().to_string(),
            attempt_id: format!("attempt:{}", operation.binding().operation_id().as_str()),
            transport_id: format!("kernel-tool-server:{}", request.server_id),
            transport_key_epoch: runtime.fence.owner_epoch,
        };
        expected_attempt.validate().map_err(|error| {
            KernelError::DurableAdmission(format!("provider attempt binding is invalid: {error}"))
        })?;
        let operation = match operation.state() {
            AdmissionOperationState::Prepared => self.apply_admission_command(
                operation,
                vec![AdmissionAttachment::BrokerAttempt(expected_attempt)],
                AdmissionOperationState::BrokerAttemptRegistered,
                trusted_now_unix_ms,
            )?,
            _ if operation.provider_attempt() == Some(&expected_attempt) => operation,
            _ => {
                return Err(KernelError::DurableAdmission(
                    "retained provider attempt does not match this dispatch".to_string(),
                ));
            }
        };
        Ok(Some(DurableToolAdmission { operation }))
    }

    pub(crate) fn durable_budget_binding(
        &self,
        admission: &DurableToolAdmission,
        capability: &CapabilityToken,
    ) -> Result<(BudgetAdmissionBinding, BudgetEventAuthority), KernelError> {
        let runtime = self.durable_runtime()?;
        let mut revocation_ids = Vec::with_capacity(capability.delegation_chain.len() + 1);
        revocation_ids.push(capability.id.clone());
        revocation_ids.extend(
            capability
                .delegation_chain
                .iter()
                .map(|link| link.capability_id.clone()),
        );
        let revocation_set =
            CanonicalRevocationSet::canonicalize(revocation_ids).map_err(|error| {
                KernelError::DurableAdmission(format!(
                    "capability revocation set is invalid: {error}"
                ))
            })?;
        Ok((
            BudgetAdmissionBinding {
                operation_id: admission.operation_id().to_string(),
                revocation_set,
                authorization_artifact_digests: Vec::new(),
                last_observed_revocation: None,
                supplemental_verifier_id: None,
                supplemental_verifier_config_digest: None,
                supplemental_authorization_artifact_digest: None,
                supplemental_authorization_expires_at: None,
            },
            runtime.authority(),
        ))
    }

    pub(crate) fn record_durable_budget_authorized(
        &self,
        admission: &mut DurableToolAdmission,
        budget_mutation: &PreExecutionBudgetMutation,
        trusted_now_unix_ms: u64,
    ) -> Result<(), KernelError> {
        let hold = budget_mutation.durable_hold_result().ok_or_else(|| {
            KernelError::DurableAdmission(
                "durable admission did not produce an authoritative budget hold".to_string(),
            )
        })?;
        let expected_authority = self.durable_runtime()?.authority();
        if hold.authorize_metadata.authority.as_ref() != Some(&expected_authority) {
            return Err(KernelError::DurableAdmission(
                "budget hold authority does not match the admission store fence".to_string(),
            ));
        }
        let expected_hold_id = admission.budget_hold_id(hold.grant_index);
        if hold.budget_hold_id != expected_hold_id {
            return Err(KernelError::DurableAdmission(
                "budget hold does not match the admission operation".to_string(),
            ));
        }
        match admission.operation.state() {
            AdmissionOperationState::BrokerAttemptRegistered => {
                admission.operation = self.apply_admission_command(
                    admission.operation.clone(),
                    vec![AdmissionAttachment::BudgetHoldId(
                        AdmissionIdentifier::try_new("budget_hold_id", expected_hold_id)?,
                    )],
                    AdmissionOperationState::BudgetAuthorized,
                    trusted_now_unix_ms,
                )?;
            }
            AdmissionOperationState::BudgetAuthorized
            | AdmissionOperationState::ReadyToDispatch
            | AdmissionOperationState::CapturePending
                if admission
                    .operation
                    .budget_hold_id()
                    .is_some_and(|hold_id| hold_id.as_str() == expected_hold_id) => {}
            state => {
                return Err(KernelError::DurableAdmission(format!(
                    "budget authorization cannot resume from state {state:?}"
                )));
            }
        }
        Ok(())
    }

    pub(crate) fn mark_durable_capture_pending(
        &self,
        admission: &mut DurableToolAdmission,
        trusted_now_unix_ms: u64,
    ) -> Result<(), KernelError> {
        if admission.operation.state() == AdmissionOperationState::BudgetAuthorized {
            admission.operation = self.apply_admission_command(
                admission.operation.clone(),
                Vec::new(),
                AdmissionOperationState::ReadyToDispatch,
                trusted_now_unix_ms,
            )?;
        }
        if admission.operation.state() == AdmissionOperationState::ReadyToDispatch {
            admission.operation = self.apply_admission_command(
                admission.operation.clone(),
                Vec::new(),
                AdmissionOperationState::CapturePending,
                trusted_now_unix_ms,
            )?;
        }
        if admission.operation.state() != AdmissionOperationState::CapturePending {
            return Err(KernelError::DurableAdmission(format!(
                "capture cannot start from state {:?}",
                admission.operation.state()
            )));
        }
        Ok(())
    }

    pub(crate) fn commit_durable_dispatch(
        &self,
        admission: &mut DurableToolAdmission,
        trusted_now_unix_ms: u64,
    ) -> Result<(), KernelError> {
        if admission.operation.state() != AdmissionOperationState::CapturePending {
            return Err(KernelError::DurableAdmission(format!(
                "dispatch cannot commit from state {:?}",
                admission.operation.state()
            )));
        }
        admission.operation = self.apply_admission_command(
            admission.operation.clone(),
            Vec::new(),
            AdmissionOperationState::DispatchCommitted,
            trusted_now_unix_ms,
        )?;
        Ok(())
    }

    fn apply_admission_command(
        &self,
        operation: AdmissionOperationV1,
        attachments: Vec<AdmissionAttachment>,
        next_state: AdmissionOperationState,
        trusted_now_unix_ms: u64,
    ) -> Result<AdmissionOperationV1, KernelError> {
        let runtime = self.durable_runtime()?;
        let expires_at_unix_ms = trusted_now_unix_ms
            .checked_add(RECOVERY_LEASE_DURATION_MS)
            .ok_or_else(|| {
                KernelError::DurableAdmission("recovery lease expiration overflowed".to_string())
            })?;
        let lease = runtime
            .store
            .claim_recovery(
                operation.binding().operation_id(),
                operation.version(),
                &runtime.claimant_id,
                trusted_now_unix_ms,
                expires_at_unix_ms,
                &runtime.fence,
            )
            .map_err(durable_store_error)?;
        let command = AdmissionOperationCommand::new(
            operation.binding().operation_id().clone(),
            operation.version(),
            lease,
            attachments,
            Some(next_state),
            None,
            None,
        )?;
        runtime
            .store
            .compare_and_swap(&command, trusted_now_unix_ms)
            .map(|result| result.into_operation())
            .map_err(durable_store_error)
    }

    fn durable_runtime(&self) -> Result<&DurableAdmissionRuntime, KernelError> {
        self.durable_admission_runtime.as_ref().ok_or_else(|| {
            KernelError::DurableAdmission(
                "qualified admission operation store is unavailable".to_string(),
            )
        })
    }
}

fn admission_digest(
    field: &'static str,
    value: &impl Serialize,
) -> Result<AdmissionDigest, KernelError> {
    let canonical = canonical_json_bytes(value)
        .map_err(|error| KernelError::DurableAdmission(format!("{field}: {error}")))?;
    AdmissionDigest::try_new(field, sha256_hex(&canonical)).map_err(KernelError::from)
}

fn durable_store_error(
    error: crate::admission_operation::AdmissionOperationStoreError,
) -> KernelError {
    KernelError::DurableAdmission(error.to_string())
}
