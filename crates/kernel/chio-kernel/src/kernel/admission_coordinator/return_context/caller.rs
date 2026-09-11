//! Private persistence of the frozen return component. The surrounding frame
//! binds physical dispatch capture; this payload is not an external permit or
//! a certificate of credential or security-hook custody.

use super::*;
use crate::admission_operation::AdmissionCallerDispatchContextV1;
use serde::{Deserialize, Serialize};

const LEGACY_SCHEMA: &str = "chio.kernel-caller-return-context.v1";
const SCHEMA: &str = "chio.kernel-caller-return-context.v2";

#[cfg(test)]
#[path = "caller/tests.rs"]
mod tests;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CallerReturnWire {
    schema: String,
    kernel_public_key: chio_core::PublicKey,
    frozen_at_unix_ms: u64,
    operation_id: crate::admission_operation::AdmissionOperationId,
    request_binding_hash: AdmissionDigest,
    request_material_digest: AdmissionDigest,
    request_id: String,
    matched_grant_index: usize,
    stream_limits: InvocationStreamLimitsV1,
    admitted_metadata: Option<serde_json::Value>,
    purchase_replay_metadata: Option<serde_json::Value>,
    recovery_replay_metadata: Option<serde_json::Value>,
    pre_invocation_guard_evidence: Vec<chio_core::receipt::metadata::GuardEvidence>,
    security_invocation_context: Option<SecurityInvocationContext>,
    federation_context_json: Option<String>,
    runtime_participant_ledger_digest: Option<AdmissionDigest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    receipt_signing_identity: Option<crate::tool_outcome::FrozenReceiptSigningIdentityV1>,
}

impl ChioKernel {
    pub(super) fn frame_caller_return_context(
        &self,
        admission: &DurableToolAdmission,
        context: &DurableToolReturnContext,
        now: u64,
    ) -> Result<Option<AdmissionCallerDispatchContextV1>, KernelError> {
        if !admission
            .operation
            .provider_attempt()
            .is_some_and(is_caller_report_attempt)
        {
            return Ok(None);
        }
        let original = admission
            .retained_request
            .as_ref()
            .ok_or_else(|| invalid("caller return context lost the original request"))?;
        if context.security_release_required {
            return Err(invalid(
                "caller snapshot cannot retain a live-only security release owner",
            ));
        }
        let wire = CallerReturnWire {
            schema: SCHEMA.into(),
            kernel_public_key: self.config.keypair.public_key(),
            receipt_signing_identity: context.receipt_signing_identity.clone(),
            frozen_at_unix_ms: now,
            operation_id: context.operation_id.clone(),
            request_binding_hash: context.request_binding_hash.clone(),
            request_material_digest: context.request_material_digest.clone(),
            request_id: context.request_id.clone(),
            matched_grant_index: context.matched_grant_index,
            stream_limits: context.stream_limits,
            admitted_metadata: context.admitted_metadata.clone(),
            purchase_replay_metadata: context.purchase_replay_metadata.clone(),
            recovery_replay_metadata: context.recovery_replay_metadata.clone(),
            pre_invocation_guard_evidence: context.pre_invocation_guard_evidence.clone(),
            security_invocation_context: context.security_invocation_context.clone(),
            federation_context_json: context
                .federation_context
                .as_ref()
                .map(|value| value.canonical_json().to_owned()),
            runtime_participant_ledger_digest: admission
                .operation
                .runtime_participant_ledger_digest()
                .cloned(),
        };
        let bytes = canonical_json_bytes(&wire).map_err(|error| invalid(error.to_string()))?;
        let frame =
            AdmissionCallerDispatchContextV1::prepare(&admission.operation, original, &bytes)
                .map_err(durable_store_error)?;
        // Reject an undecodable component before any capture is attempted.
        self.decode_caller_return_context(admission, &frame, now)?;
        Ok(Some(frame))
    }

    pub(super) fn restore_caller_return_context(
        &self,
        admission: &DurableToolAdmission,
        expected: &AdmissionCallerDispatchContextV1,
        now: u64,
    ) -> Result<DurableToolReturnContext, KernelError> {
        if admission.operation.dispatch_commit().is_none()
            || admission.operation.caller_dispatch_context_digest() != Some(expected.digest())
        {
            return Err(invalid("caller capture did not commit its frozen context"));
        }
        let runtime = self.durable_runtime()?;
        let mutation_guard = runtime.lock_mutations()?;
        let now = runtime.refresh_trusted_time(now);
        let retained = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            runtime.store.load_caller_dispatch_context(
                admission.operation.binding().operation_id(),
                &runtime.fence,
                now,
            )
        }))
        .map_err(|_| invalid("caller context read callback panicked"))?
        .map_err(durable_store_error)?
        .ok_or_else(|| invalid("caller capture lost its physical frozen context"))?;
        if retained.canonical_bytes() != expected.canonical_bytes() {
            return Err(invalid(
                "caller capture readback changed its frozen context",
            ));
        }
        // Workload and federation validation may call participant code. The
        // exact physical frame has been read back; decode outside the sequencer.
        drop(mutation_guard);
        self.decode_caller_return_context(admission, &retained, now)
    }

    fn decode_caller_return_context(
        &self,
        admission: &DurableToolAdmission,
        frame: &AdmissionCallerDispatchContextV1,
        observed_at_unix_ms: u64,
    ) -> Result<DurableToolReturnContext, KernelError> {
        let original = admission
            .retained_request
            .as_ref()
            .ok_or_else(|| invalid("caller decoding lost the original request"))?;
        let frame = AdmissionCallerDispatchContextV1::from_canonical_bytes(
            frame.canonical_bytes(),
            &admission.operation,
            original,
        )
        .map_err(durable_store_error)?;
        self.decode_caller_return_payload(
            admission,
            frame.kernel_context_json(),
            observed_at_unix_ms,
        )
    }

    fn decode_caller_return_payload(
        &self,
        admission: &DurableToolAdmission,
        bytes: &[u8],
        observed_at_unix_ms: u64,
    ) -> Result<DurableToolReturnContext, KernelError> {
        if bytes.is_empty()
            || bytes.len() > AdmissionCallerDispatchContextV1::MAX_KERNEL_CONTEXT_BYTES
        {
            return Err(invalid("caller return component exceeds its payload bound"));
        }
        let original = admission
            .retained_request
            .as_ref()
            .ok_or_else(|| invalid("caller decoding lost the original request"))?;
        let wire: CallerReturnWire =
            serde_json::from_slice(bytes).map_err(|error| invalid(error.to_string()))?;
        if canonical_json_bytes(&wire).map_err(|error| invalid(error.to_string()))? != bytes {
            return Err(invalid(
                "caller return component is not exact typed canonical JSON",
            ));
        }
        let schema_valid = match (wire.schema.as_str(), wire.receipt_signing_identity.as_ref()) {
            (SCHEMA, Some(identity)) => identity.validate().is_ok(),
            (LEGACY_SCHEMA, None) => true,
            _ => false,
        };
        if !schema_valid
            || wire.kernel_public_key != self.config.keypair.public_key()
            || wire.frozen_at_unix_ms == 0
            || wire.frozen_at_unix_ms > I_JSON_MAX_SAFE_INTEGER
            || wire.frozen_at_unix_ms > observed_at_unix_ms
            || wire.runtime_participant_ledger_digest.as_ref()
                != admission.operation.runtime_participant_ledger_digest()
        {
            return Err(invalid(
                "caller return component lost its admission binding",
            ));
        }
        let request = original.request_for_revalidation();
        self.validate_original_authority_profile(original)?;
        self.validate_security_invocation_context_binding(
            request,
            wire.security_invocation_context.as_ref(),
            None,
        )?;
        let security_binding =
            self.admission_security_binding(wire.security_invocation_context.as_ref())?;
        original
            .validate_security_binding(security_binding.as_ref())
            .map_err(durable_store_error)?;
        if wire.request_id != request.request_id
            || wire.federation_context_json.is_some()
                != request.federated_origin_kernel_id.is_some()
        {
            return Err(invalid(
                "caller return component changed its request or federation identity",
            ));
        }
        let stream_limits = InvocationStreamLimitsV1::new(
            wire.stream_limits.max_total_bytes,
            wire.stream_limits.max_chunks,
            wire.stream_limits.max_duration_secs,
        )
        .map_err(tool_outcome_error)?;
        let federation_context = wire
            .federation_context_json
            .map(|canonical| {
                self.restore_frozen_federation_return_context(
                    canonical,
                    &admission.operation,
                    request,
                    observed_at_unix_ms,
                )
            })
            .transpose()?;
        let context = DurableToolReturnContext {
            operation_id: wire.operation_id,
            request_binding_hash: wire.request_binding_hash,
            request_id: wire.request_id,
            request_material_digest: wire.request_material_digest,
            matched_grant_index: wire.matched_grant_index,
            stream_limits,
            admitted_metadata: wire.admitted_metadata,
            purchase_replay_metadata: wire.purchase_replay_metadata,
            recovery_replay_metadata: wire.recovery_replay_metadata,
            pre_invocation_guard_evidence: wire.pre_invocation_guard_evidence,
            security_invocation_context: wire.security_invocation_context,
            security_release_required: false,
            federation_context,
            receipt_signing_identity: wire.receipt_signing_identity,
        };
        context.validate_binding(admission, request)?;
        Ok(context)
    }
}

fn invalid(reason: impl Into<String>) -> KernelError {
    KernelError::DurableAdmission(reason.into())
}
