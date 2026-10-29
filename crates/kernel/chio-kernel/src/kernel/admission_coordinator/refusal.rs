use super::*;
use crate::admission_operation::RetainedToolAdmissionRequestV1;
use crate::receipt_support::{
    receipt_attribution_metadata, request_receipt_metadata_with_payee_binding,
};

pub(crate) struct DurableRefusalResponse<'a> {
    pub(crate) denial: &'a Denial,
    pub(crate) cancelled: bool,
    pub(crate) matched_grant_index: Option<usize>,
    pub(crate) metadata: Option<serde_json::Value>,
    pub(crate) verified_payee_binding: Option<&'a VerifiedGovernedPayeeBinding>,
}

impl ChioKernel {
    pub(crate) fn compensate_durable_admission_before_dispatch(
        &self,
        operation: &AdmissionOperationV1,
        verifier_policy: serde_json::Value,
        trusted_now_unix_ms: u64,
        confirmed_payment_unwind: Option<&PreDispatchPaymentUnwindEvidence>,
        response: DurableRefusalResponse<'_>,
    ) -> Result<ToolCallResponse, KernelError> {
        let runtime = self.durable_runtime()?;
        let mutation_guard = runtime.lock_mutations()?;
        let trusted_now_unix_ms = runtime.refresh_trusted_time(trusted_now_unix_ms)?;
        let current = runtime
            .store
            .load_by_operation_id(operation.binding().operation_id())
            .map_err(durable_store_error)?
            .ok_or_else(|| {
                KernelError::DurableAdmission(
                    "pre-dispatch admission disappeared during compensation".to_owned(),
                )
            })?;
        if &current != operation
            || current.state().is_terminal()
            || current.dispatch_commit().is_some()
        {
            return Err(KernelError::DurableAdmission(
                "pre-dispatch compensation operation changed".to_owned(),
            ));
        }
        let original = self.terminal_refusal_original(&current, trusted_now_unix_ms)?;
        let mut mutation_lock =
            ExternalCallLock::new(runtime, mutation_guard, &current, trusted_now_unix_ms)?;
        let lease = self.claim_admission_recovery(&current, trusted_now_unix_ms)?;
        // Runtime replay custody must be physically released before any
        // compensation can assert no effect or unwind a monetary participant.
        self.release_retained_runtime_participants(&current, &lease, trusted_now_unix_ms)?;
        self.release_retained_governed_approval(&current, &lease, trusted_now_unix_ms)?;
        self.release_retained_dpop(&current, &lease, trusted_now_unix_ms)?;
        let context = AdmissionProjectionContext {
            operation_id: current.binding().operation_id().clone(),
            request_id: current.binding().request_id().clone(),
            expected_operation_version: current.version(),
            trusted_time_unix_ms: trusted_now_unix_ms,
            coordinator_lease_id: lease.coordinator_lease_id().clone(),
            coordinator_lease_epoch: lease.coordinator_lease_epoch(),
            store_fence: runtime.fence.clone(),
        };
        self.compensate_retained_payment(
            payment_compensation::DurablePaymentCompensationInput {
                operation: &current,
                runtime,
                lease: &lease,
                context: &context,
                verifier_policy: &verifier_policy,
                confirmed_unwind: confirmed_payment_unwind,
            },
            &mut mutation_lock,
        )?;
        self.release_finding_pool_claim_before_dispatch(
            current.binding().operation_id().as_str(),
            trusted_now_unix_ms,
        )
        .map_err(|error| {
            KernelError::DurableAdmission(format!(
                "pre-dispatch finding pool claim release failed: {error}"
            ))
        })?;
        // Every budget the operation still holds is internal until dispatch
        // commits. Both the executable hold and an owned preflight hold must be
        // physically reversed before the terminal projection can claim no effect.
        self.release_retained_executable_hold(&current)?;
        if let Some(preflight) = self.load_durable_nonce_preflight(&current, trusted_now_unix_ms)? {
            self.release_durable_nonce_preflight_hold(&current, &preflight)?;
        }
        let (response, receipt) = mutation_lock.call_unlocked(&current, &lease, || {
            self.prepare_durable_refusal(
                &current,
                &original,
                &context,
                AdmissionOperationState::CompensatedBeforeDispatch,
                response,
            )
        })??;
        let projection = verified_released_pre_dispatch_compensation_projection(
            &current,
            context,
            verifier_policy,
            receipt,
        )?;
        let terminal = runtime
            .store
            .commit_admission_projection(&projection)
            .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
        if terminal.operation_id != *current.binding().operation_id()
            || terminal.state != AdmissionOperationState::CompensatedBeforeDispatch
        {
            return Err(KernelError::DurableAdmission(
                "pre-dispatch compensation committed a different terminal operation".to_owned(),
            ));
        }
        drop(mutation_lock);
        let request = original.request_for_revalidation();
        let federation = self.receipt_federation_admission_for_request(
            &request.request_id,
            request.federated_origin_kernel_id.as_deref(),
        );
        self.deliver_durable_refusal(request, response, federation.as_ref())
    }

    pub(super) fn terminal_refusal_original(
        &self,
        operation: &AdmissionOperationV1,
        trusted_now_unix_ms: u64,
    ) -> Result<RetainedToolAdmissionRequestV1, KernelError> {
        let runtime = self.durable_runtime()?;
        let (stored, original) = runtime
            .store
            .load_retained_tool_request(
                operation.binding().operation_id(),
                &runtime.fence,
                trusted_now_unix_ms,
            )
            .map_err(durable_store_error)?
            .ok_or_else(|| {
                KernelError::DurableAdmission("terminal refusal original request is absent".into())
            })?;
        if stored != *operation {
            return Err(KernelError::DurableAdmission(
                "terminal refusal original operation changed".into(),
            ));
        }
        original
            .validate_binding(operation.binding())
            .map_err(durable_store_error)?;
        Ok(original)
    }

    pub(super) fn prepare_durable_refusal(
        &self,
        operation: &AdmissionOperationV1,
        original: &RetainedToolAdmissionRequestV1,
        context: &AdmissionProjectionContext,
        state: AdmissionOperationState,
        mut response: DurableRefusalResponse<'_>,
    ) -> Result<(ToolCallResponse, VerifiedAdmissionReceipt), KernelError> {
        let identity = original.frozen_receipt_signing_identity();
        self.require_original_receipt_signer(identity)?;
        let request = original.request_for_revalidation();
        if state == AdmissionOperationState::CompensatedBeforeDispatch {
            if let Some(financial) = response
                .metadata
                .as_mut()
                .and_then(|metadata| metadata.get_mut("financial"))
                .and_then(serde_json::Value::as_object_mut)
            {
                let index = financial
                    .get("grant_index")
                    .and_then(serde_json::Value::as_u64)
                    .and_then(|index| usize::try_from(index).ok())
                    .ok_or_else(|| {
                        KernelError::DurableAdmission(
                            "terminal refusal financial grant is invalid".into(),
                        )
                    })?;
                let grant = original.retained_matching_grant(index).ok_or_else(|| {
                    KernelError::DurableAdmission(
                        "terminal refusal financial grant is not retained".into(),
                    )
                })?;
                let committed = self
                    .with_budget_store(|store| Ok(store.get_usage(&request.capability.id, index)?))?
                    .map(|usage| usage.committed_cost_units())
                    .transpose()?
                    .unwrap_or(0);
                let remaining = financial_budget_remaining(
                    grant.max_total_cost.as_ref().map(|amount| amount.units),
                    committed,
                )?;
                financial.insert("budget_remaining".into(), serde_json::json!(remaining));
            }
        }
        let compensation_status = match state {
            AdmissionOperationState::CompensatedBeforeDispatch => {
                AdmissionCompensationStatus::CompensatedBeforeDispatch
            }
            AdmissionOperationState::OutcomeUnknownAfterDispatch => {
                AdmissionCompensationStatus::NotCompensated
            }
            _ => {
                return Err(KernelError::DurableAdmission(
                    "invalid terminal refusal state".into(),
                ))
            }
        };
        let metadata = AdmissionReceiptMetadataV1 {
            schema: AdmissionReceiptSchema::V1,
            operation_id: context.operation_id.clone(),
            request_id: context.request_id.clone(),
            request_namespace_digest: operation.binding().request_namespace_digest().clone(),
            request_binding_hash: operation.binding().request_binding_hash().clone(),
            projected_operation_version: operation.version().checked_add(1).ok_or_else(|| {
                KernelError::DurableAdmission("operation version overflowed".into())
            })?,
            projected_state: state,
            projected_dispatch_state: AdmissionDispatchState::Terminal,
            trusted_time_unix_ms: context.trusted_time_unix_ms,
            coordinator_lease_id: context.coordinator_lease_id.clone(),
            coordinator_lease_epoch: context.coordinator_lease_epoch,
            store_fence: context.store_fence.clone(),
            retained_dispatch_commit: operation.dispatch_commit().cloned(),
            compensation_status,
            tool_outcome_id: None,
            tool_outcome_version: None,
        };
        let timestamp = context.trusted_time_unix_ms / 1_000;
        // After dispatch, attempt-scoped launch evidence names the attempt
        // that committed dispatch rather than the one that admitted the call.
        let admitted = original
            .admitted_receipt_metadata()
            .cloned()
            .map(|mut admitted| {
                if let Some(commit) = operation.dispatch_commit() {
                    commit.dispatch_launch.apply_to(&mut admitted);
                }
                admitted
            });
        let client_denial = (!response.cancelled).then(|| {
            serde_json::json!({
                "chio_kernel": { CLIENT_DENIAL_CODE_FIELD: response.denial.code().code() }
            })
        });
        let extra = merge_metadata_objects(
            admitted.map(serde_json::Value::Object),
            merge_metadata_objects(
                merge_metadata_objects(response.metadata, client_denial),
                Some(serde_json::json!({ ADMISSION_RECEIPT_METADATA_KEY: metadata })),
            ),
        );
        let request_metadata = request_receipt_metadata_with_payee_binding(
            request,
            self.attestation_trust_policy.as_ref(),
            timestamp,
            extra.as_ref(),
            response.verified_payee_binding,
        )?;
        let metadata = RefusalReceiptMetadata::new(
            merge_metadata_objects(
                merge_metadata_objects(request_metadata, extra),
                receipt_attribution_metadata(&request.capability, response.matched_grant_index)?,
            ),
            IdentityDisposition::Terminal,
        )
        .into_signed_metadata(operation.binding().request_namespace_digest());
        let decision = if response.cancelled {
            Decision::Cancelled {
                reason: response.denial.detail().into(),
            }
        } else {
            Decision::Deny {
                reason: response.denial.detail().into(),
                guard: "kernel".into(),
            }
        };
        let action = ToolCallAction::from_parameters(request.arguments.clone())
            .map_err(chio_core::canonical::UntrustedJsonError::Canonicalization)?;
        let content = receipt_content_for_output(None, None)?;
        let binding = operation.binding().to_persisted();
        let tenant = (binding.authenticated_tenant_id.as_str() != LOCAL_SYSTEM_TENANT_ID)
            .then(|| binding.authenticated_tenant_id.as_str().to_owned());
        let _request_tenant =
            self.scope_receipt_tenant_id_for_request(&request.request_id, tenant.clone());
        let _tenant = scope_receipt_tenant_id(tenant.clone());
        let receipt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.build_and_sign_receipt_for_identity(
                ReceiptParams {
                    request_id: Some(&request.request_id),
                    capability_id: &request.capability.id,
                    tool_name: &request.tool_name,
                    server_id: &request.server_id,
                    decision: decision.clone(),
                    action,
                    content_hash: content.content_hash,
                    canonical_content: content.canonical_content,
                    metadata,
                    timestamp,
                    trust_level: chio_core::receipt::kinds::TrustLevel::default(),
                    tenant_id: tenant,
                },
                identity.public_key(),
            )
        }))
        .map_err(|_| {
            KernelError::ReceiptSigningFailed("terminal refusal signer panicked".into())
        })??;
        let verified = VerifiedAdmissionReceipt::from_kernel_verified_refusal(
            receipt.clone(),
            identity.public_key(),
            &decision,
            &request.server_id,
            &request.tool_name,
            operation,
            context,
            state,
        )?;
        Ok((
            refusal_response(request, receipt, response.denial.code())?,
            verified,
        ))
    }

    pub(super) fn deliver_durable_refusal(
        &self,
        request: &ToolCallRequest,
        response: ToolCallResponse,
        federation: Option<&ReceiptFederationAdmission>,
    ) -> Result<ToolCallResponse, KernelError> {
        crate::kernel::security_dispatch::receipt_delivery(
            &response.receipt.id,
            ReceiptDeliveryStep::Trace,
            || {
                self.materialize_durable_admission_receipt(&response.receipt)?;
                self.mirror_durable_admission_receipt(&response.receipt)
            },
        )?;
        if request.federated_origin_kernel_id.is_some() {
            crate::kernel::security_dispatch::receipt_delivery(
                &response.receipt.id,
                ReceiptDeliveryStep::Federation,
                || {
                    if self.terminal_refusal_federation_artifacts_complete(&response.receipt)? {
                        return Ok(());
                    }
                    let missing = || {
                        KernelError::Internal(
                            "terminal refusal original federation treaty is absent".into(),
                        )
                    };
                    let admission = federation.ok_or_else(missing)?;
                    let dispatched = response
                        .receipt
                        .metadata
                        .as_ref()
                        .and_then(|metadata| {
                            metadata.pointer("/admission_operation/retained_dispatch_commit")
                        })
                        .is_some_and(|dispatch| !dispatch.is_null());
                    if dispatched && admission.verified_treaty_material.is_none() {
                        return Err(missing());
                    }
                    self.apply_federation_cosign(request, &response.receipt, Some(admission))
                },
            )?;
        }
        Ok(response)
    }

    fn terminal_refusal_federation_artifacts_complete(
        &self,
        receipt: &ChioReceipt,
    ) -> Result<bool, KernelError> {
        let now = self.trusted_now_millis()?.as_secs();
        let unavailable = || {
            KernelError::Internal(
                "terminal refusal federation artifact cache is unavailable".into(),
            )
        };
        let mut dsse = self
            .federation_dsse_envelopes
            .lock()
            .map_err(|_| unavailable())?
            .get(&receipt.id, now)
            .cloned();
        if dsse.is_none() {
            if let Some(store) = self.federation_artifact_store.as_ref() {
                dsse = store.get_dsse(&receipt.id)?;
            }
        }
        let Some(dsse) = dsse else {
            return Ok(false);
        };
        let attests = dsse
            .attests_receipt(receipt)
            .map_err(|error| KernelError::ReceiptSigningFailed(error.to_string()))?;
        if !attests {
            return Err(KernelError::Internal(
                "terminal refusal federation artifact conflicts with its receipt".into(),
            ));
        }
        Ok(true)
    }

    pub(super) fn replay_durable_refusal(
        &self,
        admission: &DurableToolAdmission,
        request: &ToolCallRequest,
    ) -> Result<ToolCallResponse, KernelError> {
        let operation = admission.operation();
        if !matches!(
            operation.state(),
            AdmissionOperationState::CompensatedBeforeDispatch
                | AdmissionOperationState::OutcomeUnknownAfterDispatch
        ) {
            return Err(KernelError::DurableAdmission(
                "invalid terminal refusal state".into(),
            ));
        }
        let runtime = self.durable_runtime()?;
        let mutation_guard = runtime.lock_mutations()?;
        let now = runtime.refresh_trusted_time(0)?;
        let original = self.terminal_refusal_original(operation, now)?;
        original
            .validate_request_material(request)
            .map_err(durable_store_error)?;
        let receipt_id = match operation.terminal_replay() {
            Some(AdmissionTerminalReplay::Receipt { receipt_id, .. }) => receipt_id,
            _ => {
                return Err(KernelError::DurableAdmission(
                    "terminal refusal receipt is absent".into(),
                ))
            }
        };
        let receipt = runtime
            .store
            .load_chio_receipt(receipt_id.as_str())?
            .ok_or_else(|| {
                KernelError::DurableAdmission("terminal refusal receipt is absent".into())
            })?;
        if runtime
            .outcome_store
            .lookup_by_operation(operation.binding().operation_id())
            .map_err(durable_outcome_store_error)?
            .is_some()
        {
            return Err(KernelError::DurableAdmission(
                "terminal refusal conflicts with a durable tool outcome".into(),
            ));
        }
        drop(mutation_guard);
        let mismatch = || {
            KernelError::DurableAdmission(
                "terminal refusal receipt conflicts with its admission".into(),
            )
        };
        let metadata: AdmissionReceiptMetadataV1 = serde_json::from_value(
            receipt
                .metadata
                .as_ref()
                .and_then(|value| value.get(ADMISSION_RECEIPT_METADATA_KEY))
                .cloned()
                .ok_or_else(mismatch)?,
        )
        .map_err(|_| mismatch())?;
        let binding = operation.binding().to_persisted();
        let tenant = (binding.authenticated_tenant_id.as_str() != LOCAL_SYSTEM_TENANT_ID)
            .then_some(binding.authenticated_tenant_id.as_str());
        let action = ToolCallAction::from_parameters(request.arguments.clone())
            .map_err(chio_core::canonical::UntrustedJsonError::Canonicalization)?;
        let identity = original.frozen_receipt_signing_identity();
        let compensation =
            if operation.state() == AdmissionOperationState::CompensatedBeforeDispatch {
                AdmissionCompensationStatus::CompensatedBeforeDispatch
            } else {
                AdmissionCompensationStatus::NotCompensated
            };
        if receipt.id != receipt_id.as_str()
            || receipt.kernel_key != *identity.public_key()
            || receipt.capability_id != request.capability.id
            || receipt.tool_server != request.server_id
            || receipt.tool_name != request.tool_name
            || canonical_json_bytes(&receipt.action)
                .map_err(chio_core::canonical::UntrustedJsonError::Canonicalization)?
                != canonical_json_bytes(&action)
                    .map_err(chio_core::canonical::UntrustedJsonError::Canonicalization)?
            || receipt.policy_hash != operation.binding().policy_hash().as_str()
            || receipt.tenant_id.as_deref() != tenant
            || receipt.content_hash != receipt_content_for_output(None, None)?.content_hash
            || receipt.timestamp != metadata.trusted_time_unix_ms / 1_000
            || metadata.operation_id != *operation.binding().operation_id()
            || metadata.request_id != *operation.binding().request_id()
            || metadata.request_namespace_digest != *operation.binding().request_namespace_digest()
            || metadata.request_binding_hash != *operation.binding().request_binding_hash()
            || metadata.projected_operation_version != operation.version()
            || metadata.projected_state != operation.state()
            || metadata.projected_dispatch_state != operation.dispatch_state()
            || metadata.coordinator_lease_epoch != operation.coordinator_lease_epoch()
            || metadata.retained_dispatch_commit.as_ref() != operation.dispatch_commit()
            || metadata.compensation_status != compensation
            || metadata.tool_outcome_id.is_some()
            || metadata.tool_outcome_version.is_some()
            || metadata.trusted_time_unix_ms == 0
            || metadata.store_fence.store_uuid != runtime.fence.store_uuid
            || metadata.store_fence.owner_epoch > runtime.fence.owner_epoch
            || receipt
                .metadata
                .as_ref()
                .and_then(|value| value.get("chio_runtime"))
                .and_then(|runtime| runtime.get(crate::kernel::runtime_field::IDENTITY_DISPOSITION))
                .and_then(serde_json::Value::as_str)
                != Some("terminal")
            || receipt
                .metadata
                .as_ref()
                .and_then(|value| value.pointer("/receipt_context/request_namespace_digest"))
                .and_then(serde_json::Value::as_str)
                != Some(operation.binding().request_namespace_digest().as_str())
        {
            return Err(mismatch());
        }
        for floor in [identity.crypto_floor(), self.receipt_signing_crypto_floor()] {
            if !receipt
                .verify_signature_with_floor(floor)
                .map_err(KernelError::ReceiptVerificationFailed)?
            {
                return Err(mismatch());
            }
        }
        let signed_code = receipt
            .metadata
            .as_ref()
            .and_then(|value| value.get("chio_kernel"))
            .and_then(|kernel| kernel.get(CLIENT_DENIAL_CODE_FIELD));
        let code = match (receipt.decision.as_ref(), signed_code) {
            (Some(Decision::Deny { .. }), Some(code)) => code
                .as_str()
                .and_then(ClientDenialCode::from_code)
                .ok_or_else(mismatch)?,
            (Some(Decision::Cancelled { .. }), None) => ClientDenialCode::Denied,
            _ => return Err(mismatch()),
        };
        self.deliver_durable_refusal(request, refusal_response(request, receipt, code)?, None)
    }
}

const CLIENT_DENIAL_CODE_FIELD: &str = "client_denial_code";

fn refusal_response(
    request: &ToolCallRequest,
    receipt: ChioReceipt,
    code: ClientDenialCode,
) -> Result<ToolCallResponse, KernelError> {
    let (reason, terminal_state, denial_code) = match receipt.decision.as_ref() {
        Some(Decision::Deny { reason, guard }) if guard == "kernel" => (
            reason.clone(),
            OperationTerminalState::Completed,
            Some(code),
        ),
        Some(Decision::Cancelled { reason }) => (
            reason.clone(),
            OperationTerminalState::Cancelled {
                reason: reason.clone(),
            },
            None,
        ),
        _ => {
            return Err(KernelError::DurableAdmission(
                "terminal refusal receipt has no refusal decision".into(),
            ))
        }
    };
    Ok(ToolCallResponse {
        request_id: request.request_id.clone(),
        verdict: Verdict::Deny,
        output: None,
        reason: Some(reason),
        denial_code,
        terminal_state,
        receipt,
        execution_nonce: None,
    })
}
