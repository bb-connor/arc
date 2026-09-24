//! Private persistence of the frozen return component. The surrounding frame
//! binds physical dispatch capture; this payload is not an external permit or
//! a certificate of credential or security-hook custody.

use super::*;
use crate::admission_operation::{
    AdmissionCallerDispatchContextV1, NativeCallerReleaseCustodyV1, NATIVE_CALLER_CONTEXT_SCHEMA,
};
use serde::{Deserialize, Serialize};

const LEGACY_SCHEMA: &str = "chio.kernel-caller-return-context.v1";
const SIGNING_SCHEMA: &str = "chio.kernel-caller-return-context.v2";
const PARTICIPANT_SCHEMA: &str = "chio.kernel-caller-return-context.v3";
const SCHEMA: &str = "chio.kernel-caller-return-context.v4";

#[path = "caller/custody.rs"]
mod custody;
#[path = "caller/report.rs"]
mod report;
pub(super) use custody::CallerParticipantCustody;

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    participants: Option<Box<FrozenDispatchParticipants>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    participant_custody: Option<CallerParticipantCustody>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    native_custody: Option<NativeCallerReleaseCustodyV1>,
}

impl ChioKernel {
    /// Publication is derived only from the fenced physical original records.
    /// The presented nonce is a selector, never a substitute for custody.
    pub(crate) fn committed_caller_authorization(
        &self,
        nonce: &crate::execution_nonce::SignedExecutionNonce,
        arguments: &serde_json::Value,
    ) -> Result<Option<crate::caller_delivery::SignedCallerDispatchAuthorizationV1>, KernelError>
    {
        use crate::caller_delivery::{
            CallerCommittedDispatchV1, CallerDispatchAuthorizationBodyV1,
            CallerInvocationBindingV1, SignedCallerDispatchAuthorizationV1,
            CALLER_DISPATCH_AUTHORIZATION_SCHEMA,
        };
        let runtime = self.durable_runtime()?;
        let guard = runtime.lock_mutations()?;
        let now = runtime.refresh_trusted_time(current_unix_timestamp_ms());
        let selector =
            AdmissionIdentifier::try_new("request_id", nonce.nonce.bound_to.request_id.clone())?;
        let (operation, original) = custody::custody_call(|| {
            runtime
                .store
                .load_unambiguous_retained_tool_request(&selector, &runtime.fence, now)
        })?
        .ok_or_else(|| invalid("caller start original request is absent"))?;
        let reservation = custody::custody_call(|| {
            runtime.store.load_execution_nonce_reservation(
                operation.binding().operation_id(),
                &runtime.fence,
                now,
            )
        })?
        .ok_or_else(|| invalid("caller start original nonce is absent"))?;
        if reservation.signed_nonce() != nonce {
            return Err(invalid(
                "caller start nonce differs from the original issuance",
            ));
        }
        let request = original.request_for_revalidation();
        let action = crate::ToolCallAction::from_parameters(arguments.clone())
            .map_err(|_| invalid("caller start arguments cannot be hashed"))?;
        if action.parameter_hash != operation.binding().action_parameter_hash().as_str() {
            return Err(invalid(
                "caller start arguments differ from the original request",
            ));
        }
        let executor = original
            .authority_profile()
            .and_then(|profile| profile.caller_executor())
            .cloned()
            .ok_or_else(|| invalid("caller start requires an originally pinned executor"))?;
        if self.caller_executor.as_ref() != Some(&executor)
            || !operation
                .provider_attempt()
                .is_some_and(is_caller_report_attempt)
        {
            return Err(invalid(
                "caller start executor or transport differs from original admission",
            ));
        }
        let Some(commit) = operation.dispatch_commit().cloned() else {
            if operation.state() != AdmissionOperationState::ReadyToDispatch {
                return Err(invalid(
                    "caller start requires a ready original reservation",
                ));
            }
            return Ok(None);
        };
        let frame = custody::custody_call(|| {
            runtime.store.load_caller_dispatch_context(
                operation.binding().operation_id(),
                &runtime.fence,
                now,
            )
        })?
        .ok_or_else(|| invalid("caller start physical context is absent"))?;
        let invocation = CallerInvocationBindingV1 {
            operation_id: operation.binding().operation_id().clone(),
            request_id: operation.binding().request_id().clone(),
            request_binding_hash: operation.binding().request_binding_hash().clone(),
            capability_id: operation.binding().capability_id().clone(),
            capability_digest: AdmissionDigest::try_new(
                "capability_digest",
                chio_core::crypto::sha256_hex(
                    &chio_core::canonical::canonical_json_bytes(&request.capability)
                        .map_err(|_| invalid("original capability cannot be hashed"))?,
                ),
            )?,
            server_id: AdmissionIdentifier::try_new("server_id", request.server_id.clone())?,
            tool_name: AdmissionIdentifier::try_new("tool_name", request.tool_name.clone())?,
            parameters_digest: operation.binding().action_parameter_hash().clone(),
        };
        let committed = CallerCommittedDispatchV1 {
            execution_nonce_id: operation
                .execution_nonce_id()
                .cloned()
                .ok_or_else(|| invalid("caller start lost its nonce identity"))?,
            budget_hold_id: operation
                .budget_hold_id()
                .cloned()
                .ok_or_else(|| invalid("caller start lost its captured hold"))?,
            dispatch_commit: commit,
            frozen_context_digest: frame.digest().clone(),
        };
        let expires_at_unix_ms = u64::try_from(nonce.expires_at())
            .ok()
            .map(|seconds| seconds.min(request.capability.expires_at))
            .and_then(|seconds| seconds.checked_mul(1_000))
            .ok_or_else(|| invalid("caller start expiry is invalid"))?;
        let admission = DurableToolAdmission {
            operation,
            retained_request: Some(original),
            issued_nonce: Some(reservation),
            aggregate_quota: None,
            supplemental_quota: None,
            nonce_preflight: None,
            _live_owner: None,
        };
        drop(guard);
        self.restore_caller_return_context(&admission, &frame, now)?;
        // Decode only after the private codec, physical custody, original
        // profile and signer checks have all succeeded.
        let wire: CallerReturnWire = serde_json::from_slice(frame.kernel_context_json())
            .map_err(|_| invalid("caller start context decoding failed"))?;
        if wire.schema != SCHEMA && wire.schema != NATIVE_CALLER_CONTEXT_SCHEMA {
            return Err(invalid(
                "legacy caller context cannot acquire start authority",
            ));
        }
        let body = CallerDispatchAuthorizationBodyV1 {
            schema: CALLER_DISPATCH_AUTHORIZATION_SCHEMA.into(),
            kernel_public_key: wire.kernel_public_key,
            executor,
            invocation,
            committed,
            not_before_unix_ms: wire.frozen_at_unix_ms,
            expires_at_unix_ms: wire
                .native_custody
                .as_ref()
                .map_or(expires_at_unix_ms, |custody| {
                    expires_at_unix_ms.min(custody.valid_until_unix_ms())
                }),
        };
        SignedCallerDispatchAuthorizationV1::sign(body, &self.config.keypair)
            .map(Some)
            .map_err(|error| invalid(error.to_string()))
    }

    pub(super) fn frame_caller_return_context(
        &self,
        admission: &DurableToolAdmission,
        context: &DurableToolReturnContext,
        now: u64,
    ) -> Result<Option<AdmissionCallerDispatchContextV1>, KernelError> {
        self.frame_caller_return_context_with_native(admission, context, now, None)
    }

    pub(in crate::kernel::admission_coordinator) fn frame_caller_return_context_with_native(
        &self,
        admission: &DurableToolAdmission,
        context: &DurableToolReturnContext,
        now: u64,
        native_custody: Option<NativeCallerReleaseCustodyV1>,
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
        if context.security_release_required != native_custody.is_some() {
            return Err(invalid(
                "caller snapshot cannot retain a live-only security release owner",
            ));
        }
        let wire = CallerReturnWire {
            schema: if native_custody.is_some() {
                NATIVE_CALLER_CONTEXT_SCHEMA
            } else {
                SCHEMA
            }
            .into(),
            native_custody,
            kernel_public_key: self.config.keypair.public_key(),
            receipt_signing_identity: context.receipt_signing_identity.clone(),
            participants: context.participants.clone(),
            participant_custody: context.caller_participant_custody.clone(),
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
        if !context.security_release_required {
            self.decode_caller_return_context(admission, &frame, now)?;
        }
        Ok(Some(frame))
    }

    pub(in crate::kernel::admission_coordinator) fn restore_caller_return_context(
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
        let schema_valid = match (
            wire.schema.as_str(),
            wire.receipt_signing_identity.as_ref(),
            wire.participants.as_ref(),
            wire.participant_custody.as_ref(),
        ) {
            (SCHEMA | NATIVE_CALLER_CONTEXT_SCHEMA, Some(identity), Some(_), Some(_))
            | (PARTICIPANT_SCHEMA, Some(identity), Some(_), None)
            | (SIGNING_SCHEMA, Some(identity), None, None) => identity.validate().is_ok(),
            (LEGACY_SCHEMA, None, None, None) => true,
            _ => false,
        };
        if !schema_valid
            || (wire.schema == NATIVE_CALLER_CONTEXT_SCHEMA) != wire.native_custody.is_some()
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
        if let Some(custody) = wire.participant_custody.as_ref() {
            let retained = self.read_caller_participant_custody(
                admission,
                wire.matched_grant_index,
                observed_at_unix_ms,
            )?;
            if custody != &retained {
                return Err(invalid(
                    "caller context changed its original participant episodes",
                ));
            }
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
            security_release_required: wire.native_custody.is_some(),
            caller_delivery_evidence: None,
            federation_context,
            receipt_signing_identity: wire.receipt_signing_identity,
            participants: wire.participants,
            caller_participant_custody: wire.participant_custody,
        };
        context.validate_binding(admission, request)?;
        Ok(context)
    }
}

fn invalid(reason: impl Into<String>) -> KernelError {
    KernelError::DurableAdmission(reason.into())
}
