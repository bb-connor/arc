//! Restore only the release owner of an authenticated, recorded native return.
use super::*;
use crate::budget_store::{BudgetInvocationCaptureDecision, BudgetInvocationState};
use crate::kernel::admission_coordinator::security_release::DurableSecurityReleaseInput;

impl ChioKernel {
    pub(in crate::kernel::admission_coordinator) fn recover_recorded_native_release_owner(
        &self,
        input: &DurableSecurityReleaseInput<'_>,
    ) -> Result<Option<SecurityRequestLifecycleHandle>, KernelError> {
        let admission = input.admission;
        let operation = &admission.operation;
        let Some(original) = admission.original_retained_request() else {
            return Ok(None);
        };
        let Some(binding) = original.native_security_authority_binding() else {
            return Ok(None);
        };
        let request = input
            .raw
            .recovery_request()
            .map_err(|_| invalid("recorded native release request is invalid"))?
            .ok_or_else(|| invalid("recorded native release request is absent"))?;
        let expected_transport =
            DispatchTransport::KernelToolServer.transport_id(&request.server_id);
        if operation
            .provider_attempt()
            .is_none_or(|attempt| attempt.transport_id != expected_transport)
        {
            // Caller-report delivery has separate nonce, executor and report
            // authority. A native preparation cannot replace that evidence.
            return Ok(None);
        }
        let context = input
            .raw
            .security_invocation_context()
            .ok_or_else(|| invalid("recorded native release context is absent"))?;
        if operation.state() != AdmissionOperationState::Finalizing
            || operation.dispatch_commit().is_none()
            || operation.native_dispatch_ledger_digest().is_none()
            || original.authority_profile().is_none()
            || input.raw.caller_delivery_evidence().is_some()
            || !input
                .raw
                .requires_security_release()
                .map_err(|_| invalid("recorded native release requirement is unqualified"))?
        {
            return Err(invalid(
                "recorded native release lacks original finalization custody",
            ));
        }
        original
            .validate_binding(operation.binding())
            .and_then(|()| original.validate_request_material(&request))
            .and_then(|()| original.validate_native_security_context(context))
            .map_err(durable_store_error)?;
        let grant = input
            .raw
            .matched_grant_index()
            .map_err(|_| invalid("recorded native release grant is invalid"))?;
        if !admission.permits_grant(grant) || original.retained_matching_grant(grant).is_none() {
            return Err(invalid(
                "recorded native release changed the original grant",
            ));
        }

        let runtime = self.durable_runtime()?;
        let guard = runtime.lock_mutations()?;
        let now = runtime.refresh_trusted_time(current_unix_timestamp_ms());
        let operation_id = operation.binding().operation_id();
        let (physical, retained) = store_call(|| {
            runtime
                .store
                .load_retained_tool_request(operation_id, &runtime.fence, now)
        })?
        .ok_or_else(|| invalid("recorded native release original is absent"))?;
        let capture = store_call(|| {
            runtime
                .store
                .load_native_dispatch_capture(operation_id, &runtime.fence, now)
        })?
        .ok_or_else(|| invalid("recorded native release physical budget capture is absent"))?;
        let BudgetInvocationCaptureDecision::Captured(decision) = &capture.decision else {
            return Err(invalid(
                "recorded native release requires original physical capture",
            ));
        };
        let ledger = store_call(|| {
            runtime
                .store
                .load_native_dispatch_ledger(operation_id, &runtime.fence, now)
        })?
        .ok_or_else(|| invalid("recorded native release dispatch ledger is absent"))?;
        retained
            .validate_native_security_authority(binding)
            .and_then(|()| retained.validate_native_security_context(context))
            .and_then(|()| retained.validate_request_material(&request))
            .map_err(durable_store_error)?;
        if &physical != operation
            || &capture.operation != operation
            || retained.canonical_bytes() != original.canonical_bytes()
            || decision.invocation_state != BudgetInvocationState::Captured
            || decision
                .admission_binding
                .as_ref()
                .is_none_or(|captured| captured.operation_id != operation_id.as_str())
            || ledger.operation_id != *operation_id
            || Some(&ledger.record_digest) != operation.native_dispatch_ledger_digest()
            || ledger.record_digest.as_str() != sha256_hex(&ledger.canonical_record)
            || ledger.canonical_record.is_empty()
            || ledger.canonical_record.len() > 1024 * 1024
        {
            return Err(invalid(
                "recorded native release changed its physical capture",
            ));
        }
        let canonical = canonical_live_request(&request)?;
        let ledger_body: serde_json::Value = serde_json::from_slice(&ledger.canonical_record)
            .map_err(|_| invalid("recorded native release ledger is invalid"))?;
        let context_body = serde_json::to_value(context)
            .map_err(|_| invalid("recorded native release context cannot encode"))?;
        if ledger_body
            .get("schema")
            .and_then(serde_json::Value::as_str)
            != Some("chio.native-dispatch-preparation-ledger.v1")
            || ledger_body.get("context") != Some(&context_body)
            || ledger_body
                .get("grant_index")
                .and_then(serde_json::Value::as_u64)
                != u64::try_from(grant).ok()
            || ledger_body
                .get("live_request_digest")
                .and_then(serde_json::Value::as_str)
                != Some(sha256_hex(&canonical).as_str())
            || canonical_json_bytes(&ledger_body)
                .map_err(|_| invalid("recorded native ledger cannot encode"))?
                != ledger.canonical_record
        {
            return Err(invalid(
                "recorded native release differs from its frozen dispatch",
            ));
        }
        let recorded_raw = runtime
            .outcome_store
            .load_raw_invocation_by_operation(operation_id)
            .map_err(durable_outcome_store_error)?
            .ok_or_else(|| invalid("recorded native release raw return is absent"))?;
        let recorded_outcome = runtime
            .outcome_store
            .lookup_by_operation(operation_id)
            .map_err(durable_outcome_store_error)?
            .ok_or_else(|| invalid("recorded native release outcome is absent"))?;
        let recorded_evaluation = runtime
            .outcome_store
            .lookup_post_return_evaluation(operation_id)
            .map_err(durable_outcome_store_error)?
            .ok_or_else(|| invalid("recorded native release evaluation is absent"))?;
        if &recorded_raw != input.raw
            || &recorded_outcome != input.outcome
            || &recorded_evaluation != input.evaluation
        {
            return Err(invalid(
                "recorded native release changed its protected return artifacts",
            ));
        }
        input
            .outcome
            .validate_canonical_blob(
                operation,
                &recorded_raw
                    .canonical_blob()
                    .map_err(|_| invalid("recorded native release raw return is invalid"))?,
            )
            .map_err(|_| invalid("recorded native release outcome binding is invalid"))?;
        input
            .evaluation
            .validate_against(operation, input.outcome)
            .map_err(|_| invalid("recorded native release evaluation binding is invalid"))?;
        drop(guard);
        let dispatch_commitment_id = input
            .raw
            .security_dispatch_commitment_id()
            .map_err(|_| invalid("recorded native release dispatch commitment is invalid"))?;
        let dispatch = SecurityPreDispatchContext {
            request: &request,
            canonical_request: &canonical,
            security_context: context,
            dispatch_commitment_id: &dispatch_commitment_id,
        };
        // This is the same release-only owner as live native capture. The
        // common output writer and checkpoint still require the exact current
        // finalization lease. Nothing here can capture, submit or renew a call.
        Ok(Some(SecurityRequestLifecycleHandle::new(
            Box::new(NativeReleaseOwner {
                captured: operation.clone(),
                context: context.clone(),
            }),
            &dispatch,
        )))
    }
}
